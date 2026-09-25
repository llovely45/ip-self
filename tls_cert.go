package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxTLSNames = 32

func configureTLSWithReader(reader *bufio.Reader, configPath string) (string, string, error) {
	fmt.Println("非回环监听必须使用 TLS。证书配置方式：")
	fmt.Println("1) 使用已有证书和私钥")
	fmt.Println("2) 生成自签名证书（客户端需要手动信任）")
	choice, err := prompt(reader, "选择 1/2")
	if err != nil {
		return "", "", err
	}

	switch choice {
	case "1":
		certFile, err := prompt(reader, "TLS 证书文件路径")
		if err != nil {
			return "", "", err
		}
		keyFile, err := prompt(reader, "TLS 私钥文件路径")
		if err != nil {
			return "", "", err
		}
		if certFile == "" || keyFile == "" {
			return "", "", errors.New("TLS certificate and key paths are required for a non-loopback listener")
		}
		certFile, err = filepath.Abs(certFile)
		if err != nil {
			return "", "", err
		}
		keyFile, err = filepath.Abs(keyFile)
		if err != nil {
			return "", "", err
		}
		if _, err := os.Stat(certFile); err != nil {
			return "", "", fmt.Errorf("TLS certificate is not readable: %w", err)
		}
		if info, err := os.Stat(keyFile); err != nil {
			return "", "", fmt.Errorf("TLS private key is not readable: %w", err)
		} else if info.Mode().Perm()&0077 != 0 {
			return "", "", errors.New("TLS private key permissions are too broad; restrict it to owner access (for example chmod 600)")
		}
		if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
			return "", "", fmt.Errorf("invalid TLS certificate/key pair: %w", err)
		}
		return certFile, keyFile, nil

	case "2":
		value, err := prompt(reader, "客户端连接 API 时使用的域名/IP（逗号分隔，如 api.example.com,203.0.113.10）")
		if err != nil {
			return "", "", err
		}
		dnsNames, ipAddresses, canonicalNames, err := parseTLSNames(value)
		if err != nil {
			return "", "", err
		}
		certFile, keyFile, fingerprint, err := generateSelfSignedTLSCert(configPath, dnsNames, ipAddresses)
		if err != nil {
			return "", "", err
		}
		fmt.Printf("自签名证书已生成：%s\n私钥：%s\nSHA-256 指纹：%s\n", certFile, keyFile, fingerprint)
		fmt.Printf("证书包含的域名/IP：%s\n", strings.Join(canonicalNames, ", "))
		fmt.Println("请安全地把证书文件复制到客户端，并使用 curl --cacert <证书文件> 校验证书；不要使用 -k/--insecure。")
		return certFile, keyFile, nil

	default:
		return "", "", errors.New("unknown TLS certificate selection")
	}
}

func parseTLSNames(value string) ([]string, []net.IP, []string, error) {
	if len(value) > 4096 {
		return nil, nil, nil, errors.New("TLS name list is too long")
	}
	parts := strings.Split(value, ",")
	if len(parts) == 0 || len(parts) > maxTLSNames {
		return nil, nil, nil, fmt.Errorf("enter between 1 and %d TLS names", maxTLSNames)
	}

	dnsNames := make([]string, 0, len(parts))
	ipAddresses := make([]net.IP, 0, len(parts))
	canonicalNames := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		name := strings.TrimSpace(part)
		if strings.HasPrefix(name, "[") && strings.HasSuffix(name, "]") {
			name = strings.TrimSuffix(strings.TrimPrefix(name, "["), "]")
		}
		if name == "" {
			return nil, nil, nil, errors.New("TLS name list contains an empty value")
		}

		if address, err := netip.ParseAddr(name); err == nil {
			if address.Zone() != "" {
				return nil, nil, nil, errors.New("IPv6 zone identifiers are not valid certificate names")
			}
			canonical := address.String()
			if _, exists := seen[canonical]; exists {
				return nil, nil, nil, fmt.Errorf("duplicate TLS name %q", canonical)
			}
			seen[canonical] = struct{}{}
			ipAddresses = append(ipAddresses, net.IP(address.AsSlice()))
			canonicalNames = append(canonicalNames, canonical)
			continue
		}

		name = strings.ToLower(name)
		if looksLikeIPv4Address(name) {
			return nil, nil, nil, fmt.Errorf("invalid IPv4 certificate name %q", name)
		}
		if !validTLSDNSName(name) {
			return nil, nil, nil, fmt.Errorf("invalid TLS DNS name %q; use ASCII/Punycode DNS names or IP addresses", name)
		}
		if _, exists := seen[name]; exists {
			return nil, nil, nil, fmt.Errorf("duplicate TLS name %q", name)
		}
		seen[name] = struct{}{}
		dnsNames = append(dnsNames, name)
		canonicalNames = append(canonicalNames, name)
	}
	return dnsNames, ipAddresses, canonicalNames, nil
}

func looksLikeIPv4Address(value string) bool {
	if !strings.Contains(value, ".") {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && char != '.' {
			return false
		}
	}
	return true
}

func validTLSDNSName(name string) bool {
	if len(name) == 0 || len(name) > 253 || strings.HasSuffix(name, ".") {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return true
}

func generateSelfSignedTLSCert(configPath string, dnsNames []string, ipAddresses []net.IP) (string, string, string, error) {
	if len(dnsNames)+len(ipAddresses) == 0 {
		return "", "", "", errors.New("at least one TLS DNS name or IP address is required")
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", "", fmt.Errorf("generate TLS private key: %w", err)
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", "", fmt.Errorf("generate TLS certificate serial: %w", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "ip-self"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		DNSNames:              append([]string(nil), dnsNames...),
		IPAddresses:           append([]net.IP(nil), ipAddresses...),
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", "", "", fmt.Errorf("create self-signed TLS certificate: %w", err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", "", "", fmt.Errorf("encode TLS private key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER})
	directory := filepath.Join(filepath.Dir(configPath), "tls")
	if err := os.MkdirAll(directory, 0700); err != nil {
		return "", "", "", fmt.Errorf("create TLS directory: %w", err)
	}
	if err := validateConfigDirectory(directory); err != nil {
		return "", "", "", fmt.Errorf("TLS directory is not secure: %w", err)
	}

	certFile := filepath.Join(directory, "server.crt")
	keyFile := filepath.Join(directory, "server.key")
	for _, path := range []string{certFile, keyFile} {
		if _, err := os.Lstat(path); err == nil {
			return "", "", "", fmt.Errorf("refusing to overwrite existing TLS file %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", "", "", fmt.Errorf("inspect TLS file %s: %w", path, err)
		}
	}

	certTemp, err := writeTLSFileTemp(directory, ".ip-self-cert-*", certPEM, 0644)
	if err != nil {
		return "", "", "", err
	}
	defer os.Remove(certTemp)
	keyTemp, err := writeTLSFileTemp(directory, ".ip-self-key-*", keyPEM, 0600)
	if err != nil {
		return "", "", "", err
	}
	defer os.Remove(keyTemp)
	if err := os.Rename(certTemp, certFile); err != nil {
		return "", "", "", fmt.Errorf("install TLS certificate: %w", err)
	}
	if err := os.Rename(keyTemp, keyFile); err != nil {
		_ = os.Remove(certFile)
		return "", "", "", fmt.Errorf("install TLS private key: %w", err)
	}

	dirHandle, err := os.Open(directory)
	if err != nil {
		return "", "", "", fmt.Errorf("open TLS directory for sync: %w", err)
	}
	defer dirHandle.Close()
	if err := dirHandle.Sync(); err != nil {
		return "", "", "", fmt.Errorf("sync TLS directory: %w", err)
	}
	fingerprint := sha256.Sum256(certificateDER)
	return certFile, keyFile, hex.EncodeToString(fingerprint[:]), nil
}

func writeTLSFileTemp(directory, pattern string, data []byte, mode os.FileMode) (string, error) {
	file, err := os.CreateTemp(directory, pattern)
	if err != nil {
		return "", fmt.Errorf("create temporary TLS file: %w", err)
	}
	path := file.Name()
	removeOnError := true
	defer func() {
		if removeOnError {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return "", fmt.Errorf("set TLS file permissions: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return "", fmt.Errorf("write TLS file: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return "", fmt.Errorf("sync TLS file: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close TLS file: %w", err)
	}
	removeOnError = false
	return path, nil
}
