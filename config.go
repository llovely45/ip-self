package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

const (
	defaultListenAddr    = ":38853"
	maxTargetPorts       = 32
	maxAllowedIPs        = 256
	maxManagedAllowRules = 1024
)

type Config struct {
	Version    int    `json:"version"`
	Token      string `json:"token"`
	ListenAddr string `json:"listen_addr"`
	APIHost    string `json:"api_host,omitempty"`
	// These legacy fields are retained so existing v0.2.x configurations load.
	// The API now always uses plain HTTP and ignores both values.
	TLSCertFile string   `json:"tls_cert_file,omitempty"`
	TLSKeyFile  string   `json:"tls_key_file,omitempty"`
	Firewall    string   `json:"firewall"`
	TargetPorts []int    `json:"target_tcp_ports"`
	AllowedIPs  []string `json:"allowed_ips"`
}

func defaultConfigPath() string {
	if runtime.GOOS == "linux" {
		return "/etc/ip-self/config.json"
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return filepath.Join(".", "ip-self", "config.json")
	}
	return filepath.Join(base, "ip-self", "config.json")
}

func loadConfig(path string) (Config, error) {
	var cfg Config
	info, err := os.Lstat(path)
	if err != nil {
		return cfg, err
	}
	if err := validateConfigDirectory(filepath.Dir(path)); err != nil {
		return cfg, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return cfg, errors.New("configuration must be a regular, non-symlink file")
	}
	if info.Mode().Perm()&0077 != 0 {
		return cfg, errors.New("configuration permissions are too broad; expected 0600 or stricter")
	}
	if !secureConfigOwner(info) {
		return cfg, errors.New("configuration file must be owned by root when used by the root service")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read configuration: %w", err)
	}
	if len(data) > 1<<20 {
		return cfg, errors.New("configuration file exceeds 1 MiB")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("parse configuration: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return cfg, errors.New("configuration contains trailing data")
	}
	if err := validateConfig(cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func saveConfig(path string, cfg Config) error {
	if err := validateConfig(cfg); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create configuration directory: %w", err)
	}
	if err := validateConfigDirectory(dir); err != nil {
		return err
	}
	if oldInfo, err := os.Lstat(path); err == nil {
		if !oldInfo.Mode().IsRegular() || oldInfo.Mode()&os.ModeSymlink != 0 || oldInfo.Mode().Perm()&0077 != 0 {
			return errors.New("refusing to replace an unsafe configuration file")
		}
		if !secureConfigOwner(oldInfo) {
			return errors.New("refusing to replace a configuration file not owned by root")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect configuration file: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".ip-self-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary configuration: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return fmt.Errorf("protect temporary configuration: %w", err)
	}
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cfg); err != nil {
		tmp.Close()
		return fmt.Errorf("write configuration: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync configuration: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close configuration: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("install configuration: %w", err)
	}
	dirHandle, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open configuration directory for sync: %w", err)
	}
	defer dirHandle.Close()
	if err := dirHandle.Sync(); err != nil {
		return fmt.Errorf("sync configuration directory: %w", err)
	}
	return nil
}

func validateConfigDirectory(path string) error {
	current := filepath.Clean(path)
	for {
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect configuration directory %s: %w", current, err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.New("configuration directory path must contain only non-symlink directories not writable by group or others")
		}
		if !secureConfigOwner(info) {
			return fmt.Errorf("configuration directory %s must be owned by root when used by the root service", current)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

func validateConfig(cfg Config) error {
	if cfg.Version != 1 {
		return fmt.Errorf("unsupported configuration version %d", cfg.Version)
	}
	if err := validateToken(cfg.Token); err != nil {
		return err
	}
	controlPort, err := portFromListenAddr(cfg.ListenAddr)
	if err != nil {
		return err
	}
	if !validAPIHost(cfg.APIHost) {
		return errors.New("API display host must be a DNS name or IP address without a scheme or port")
	}
	switch cfg.Firewall {
	case "ufw", "iptables", "nftables":
	default:
		return errors.New("firewall must be ufw, iptables, or nftables")
	}
	if len(cfg.TargetPorts) == 0 || len(cfg.TargetPorts) > maxTargetPorts {
		return fmt.Errorf("configure between 1 and %d protected TCP ports", maxTargetPorts)
	}
	seenPorts := make(map[int]struct{}, len(cfg.TargetPorts))
	for _, port := range cfg.TargetPorts {
		if port < 1 || port > 65535 || port == controlPort {
			return fmt.Errorf("invalid protected TCP port %d (control port %d cannot be protected)", port, controlPort)
		}
		if _, ok := seenPorts[port]; ok {
			return fmt.Errorf("duplicate protected TCP port %d", port)
		}
		seenPorts[port] = struct{}{}
	}
	if len(cfg.AllowedIPs) > maxAllowedIPs {
		return fmt.Errorf("allowlist exceeds the %d address limit", maxAllowedIPs)
	}
	if len(cfg.AllowedIPs)*len(cfg.TargetPorts) > maxManagedAllowRules {
		return fmt.Errorf("allowlist and target ports would exceed the %d managed firewall rule limit", maxManagedAllowRules)
	}
	seenIPs := make(map[string]struct{}, len(cfg.AllowedIPs))
	for _, value := range cfg.AllowedIPs {
		addr, err := parseClientIP(value)
		if err != nil || addr.String() != value {
			return fmt.Errorf("invalid or non-canonical allowed IP %q", value)
		}
		if _, ok := seenIPs[value]; ok {
			return fmt.Errorf("duplicate allowed IP %q", value)
		}
		seenIPs[value] = struct{}{}
	}
	return nil
}

func portFromListenAddr(address string) (int, error) {
	_, portText, err := net.SplitHostPort(address)
	if err != nil {
		return 0, fmt.Errorf("invalid listen address: %w", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("listen port must be between 1 and 65535")
	}
	return port, nil
}

func configuredControlPort(cfg Config) int {
	port, _ := portFromListenAddr(cfg.ListenAddr)
	return port
}

func validAPIHost(host string) bool {
	if host == "" {
		return true
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Zone() == ""
	}
	if len(host) > 253 || strings.ContainsAny(host, ":/\\ \t\r\n") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return true
}

func sortedIPs(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}
