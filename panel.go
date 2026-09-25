package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

func runPanel(configPath string) error {
	reader := bufio.NewReader(os.Stdin)
	for {
		cfg, loadErr := loadConfig(configPath)
		configured := loadErr == nil
		fmt.Println("\nip-self 控制面板")
		if configured {
			fmt.Printf("API: %s | 防火墙: %s | 目标端口: %s | 已放行 IP: %d\n", cfg.ListenAddr, cfg.Firewall, formatPorts(cfg.TargetPorts), len(cfg.AllowedIPs))
		} else if errors.Is(loadErr, os.ErrNotExist) {
			fmt.Println("尚未初始化")
		} else {
			fmt.Printf("配置不可用: %v\n", loadErr)
		}
		fmt.Println("1) 初始化（生成固定 UUIDv7 Token 并选择目标端口与防火墙）")
		fmt.Println("2) 显示 Token")
		fmt.Println("3) 查看状态和放行 IP")
		fmt.Println("4) 重新应用防火墙规则")
		fmt.Println("5) 后台启动 API 服务")
		fmt.Println("0) 退出")
		choice, err := prompt(reader, "选择")
		if err != nil {
			return err
		}
		switch choice {
		case "1":
			if configured {
				fmt.Println("配置已初始化，Token 固定且不会被覆盖。")
				continue
			}
			if loadErr != nil && !errors.Is(loadErr, os.ErrNotExist) {
				fmt.Printf("先处理配置错误：%v\n", loadErr)
				continue
			}
			if err := initializeWithReader(configPath, reader); err != nil {
				fmt.Println("初始化失败：", err)
			} else {
				fmt.Println("初始化完成。请把显示的 Token 安全保存。")
			}
		case "2":
			if !configured {
				fmt.Println("请先初始化。")
				continue
			}
			fmt.Printf("API Token: %s\n", cfg.Token)
		case "3":
			if configured {
				printStatus(cfg, configPath)
			} else {
				fmt.Printf("配置不可用：%v\n", loadErr)
			}
		case "4":
			if !configured {
				fmt.Println("请先初始化。")
				continue
			}
			if err := firewallSetup(cfg); err != nil {
				fmt.Println("应用防火墙规则失败：", err)
			} else {
				fmt.Println("防火墙规则已重新应用。")
			}
		case "5":
			if !configured {
				fmt.Println("请先初始化。")
				continue
			}
			pid, logPath, err := startBackgroundServer(configPath)
			if err != nil {
				fmt.Println("后台启动 API 服务失败：", err)
				continue
			}
			fmt.Printf("API 服务已在后台启动（PID %d）。\n", pid)
			fmt.Printf("日志文件：%s\n", logPath)
			fmt.Printf("停止服务：sudo kill %d\n", pid)
			return nil
		case "0":
			return nil
		default:
			fmt.Println("请输入菜单编号。")
		}
	}
}

func initialize(configPath string) error {
	return initializeWithReader(configPath, bufio.NewReader(os.Stdin))
}

func initializeWithReader(configPath string, reader *bufio.Reader) error {
	if runtime.GOOS != "linux" {
		return errors.New("initial setup and firewall management require Linux")
	}
	if err := requireLinuxRoot(); err != nil {
		return err
	}
	if _, err := os.Lstat(configPath); err == nil {
		return errors.New("configuration already exists; the token is fixed and will not be overwritten")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect existing configuration: %w", err)
	}

	listenAddr, err := promptDefault(reader, "监听地址（端口固定 38853）", defaultListenAddr)
	if err != nil {
		return err
	}
	if _, port, err := net.SplitHostPort(listenAddr); err != nil || port != strconv.Itoa(controlPort) {
		return fmt.Errorf("监听地址必须使用端口 %d，例如 :%d 或 127.0.0.1:%d", controlPort, controlPort, controlPort)
	}
	var certFile, keyFile string
	if !isLoopbackListener(listenAddr) {
		certFile, keyFile, err = configureTLSWithReader(reader, configPath)
		if err != nil {
			return err
		}
	}

	ports, err := promptPorts(reader)
	if err != nil {
		return err
	}
	allowedIPs, err := promptInitialIPs(reader)
	if err != nil {
		return err
	}
	fmt.Println("防火墙后端：")
	fmt.Println("1) UFW（要求已经启用）")
	fmt.Println("2) iptables + ip6tables（要求 UFW 未启用）")
	fmt.Println("3) nftables（要求 UFW 未启用）")
	backendChoice, err := prompt(reader, "选择 1/2/3")
	if err != nil {
		return err
	}
	backends := map[string]string{"1": "ufw", "2": "iptables", "3": "nftables"}
	backend, ok := backends[backendChoice]
	if !ok {
		return errors.New("unknown firewall selection")
	}
	if err := preflightFirewall(backend); err != nil {
		return fmt.Errorf("firewall preflight failed before saving configuration: %w", err)
	}
	fmt.Printf("\n控制端口 TCP %d 将允许连接后再验证 TLS + Bearer。目标端口 TCP %s 将默认拒绝，只允许白名单来源。\n", controlPort, formatPorts(ports))
	fmt.Printf("所选防火墙：%s。初始白名单 IP 数：%d。\n", backend, len(allowedIPs))
	if len(allowedIPs) == 0 {
		fmt.Println("当前初始白名单为空；初始化后目标端口的新连接都会被拒绝。你可以从当前公网 IP 调用认证 API 加入白名单。")
	}
	confirmation, err := prompt(reader, "输入 APPLY 以安装这组防火墙规则")
	if err != nil {
		return err
	}
	if confirmation != "APPLY" {
		return errors.New("firewall setup cancelled")
	}
	token, err := newUUIDv7()
	if err != nil {
		return err
	}
	cfg := Config{
		Version:     1,
		Token:       token,
		ListenAddr:  listenAddr,
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
		Firewall:    backend,
		TargetPorts: ports,
		AllowedIPs:  allowedIPs,
	}
	if err := saveConfig(configPath, cfg); err != nil {
		return err
	}
	fmt.Printf("\nToken（UUIDv7，已保存且固定）：%s\n", token)
	if err := firewallSetup(cfg); err != nil {
		return fmt.Errorf("配置已安全保存，但防火墙规则未完成；可运行 `sudo ip-self firewall` 重试：%w", err)
	}
	return nil
}

func promptInitialIPs(reader *bufio.Reader) ([]string, error) {
	for {
		text, err := prompt(reader, "初始白名单 IP（可空；多个地址用逗号分隔）")
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(text) == "" {
			return []string{}, nil
		}
		parts := strings.Split(text, ",")
		ips := make([]string, 0, len(parts))
		seen := map[string]bool{}
		valid := len(parts) <= maxAllowedIPs
		for _, part := range parts {
			addr, parseErr := parseClientIP(strings.TrimSpace(part))
			if parseErr != nil || seen[addr.String()] {
				valid = false
				break
			}
			seen[addr.String()] = true
			ips = append(ips, addr.String())
		}
		if valid {
			sort.Strings(ips)
			return ips, nil
		}
		fmt.Printf("地址无效；请提供最多 %d 个不重复的单播 IP。\n", maxAllowedIPs)
	}
}

func promptPorts(reader *bufio.Reader) ([]int, error) {
	for {
		text, err := prompt(reader, "受保护的目标 TCP 端口列表（逗号分隔，如 22,80,443）")
		if err != nil {
			return nil, err
		}
		parts := strings.Split(text, ",")
		ports := make([]int, 0, len(parts))
		seen := map[int]bool{}
		valid := true
		for _, part := range parts {
			value := strings.TrimSpace(part)
			port, parseErr := strconv.Atoi(value)
			if parseErr != nil || port < 1 || port > 65535 || port == controlPort || seen[port] {
				valid = false
				break
			}
			seen[port] = true
			ports = append(ports, port)
		}
		if valid && len(ports) > 0 && len(ports) <= maxTargetPorts {
			sort.Ints(ports)
			return ports, nil
		}
		fmt.Printf("端口列表无效；请给出 1 至 %d 个不重复端口，且不能包含控制端口 %d。\n", maxTargetPorts, controlPort)
	}
}

func prompt(reader *bufio.Reader, label string) (string, error) {
	fmt.Printf("%s: ", label)
	line, err := reader.ReadString('\n')
	if err != nil && len(line) == 0 {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func promptDefault(reader *bufio.Reader, label, defaultValue string) (string, error) {
	value, err := prompt(reader, fmt.Sprintf("%s [%s]", label, defaultValue))
	if err != nil {
		return "", err
	}
	if value == "" {
		return defaultValue, nil
	}
	return value, nil
}

func printStatus(cfg Config, configPath string) {
	fmt.Println("配置状态:")
	fmt.Printf("  配置文件: %s\n", configPath)
	fmt.Printf("  监听地址: %s\n", cfg.ListenAddr)
	fmt.Printf("  Token: UUIDv7（固定；使用 `ip-self token` 查看）\n")
	fmt.Printf("  防火墙: %s\n", cfg.Firewall)
	fmt.Printf("  受保护 TCP 端口: %s\n", formatPorts(cfg.TargetPorts))
	fmt.Printf("  已放行 IP: %d\n", len(cfg.AllowedIPs))
	for _, ip := range cfg.AllowedIPs {
		fmt.Printf("    %s\n", ip)
	}
}
