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
			fmt.Printf("HTTP API: %s | 防火墙: %s | 目标端口: %s | 已放行 IP: %d\n", cfg.ListenAddr, cfg.Firewall, formatPorts(cfg.TargetPorts), len(cfg.AllowedIPs))
		} else if errors.Is(loadErr, os.ErrNotExist) {
			fmt.Println("尚未初始化")
		} else {
			fmt.Printf("配置不可用: %v\n", loadErr)
		}
		fmt.Println("1) 初始化（生成固定 UUIDv7 Token 并选择监听端口、目标端口与防火墙）")
		fmt.Println("2) 显示 Token")
		fmt.Println("3) 查看状态和放行 IP")
		fmt.Println("4) 重新应用防火墙规则")
		fmt.Println("5) 后台启动 HTTP API 服务")
		fmt.Println("6) 修改 HTTP API 监听端口")
		fmt.Println("7) 显示 API 地址和 curl 命令")
		fmt.Println("8) 设置 curl 使用的服务器 IP/域名")
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
			fmt.Printf("HTTP API 服务已在后台启动（PID %d）。\n", pid)
			fmt.Printf("日志文件：%s\n", logPath)
			fmt.Printf("停止服务：sudo kill %d\n", pid)
			return nil
		case "6":
			if !configured {
				fmt.Println("请先初始化。")
				continue
			}
			if err := updateAPIListenPort(cfg, configPath, reader); err != nil {
				fmt.Println("修改 API 监听端口失败：", err)
			} else {
				fmt.Println("API 监听端口和防火墙规则已更新。请重新启动 HTTP API 服务。")
			}
		case "7":
			if !configured {
				fmt.Println("请先初始化。")
				continue
			}
			printCurlCommand(cfg)
		case "8":
			if !configured {
				fmt.Println("请先初始化。")
				continue
			}
			if err := updateAPIHost(cfg, configPath, reader); err != nil {
				fmt.Println("设置服务器 IP/域名失败：", err)
			} else {
				fmt.Println("curl 访问地址已更新。")
			}
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

	listenAddr, err := promptDefault(reader, "HTTP API 监听地址（例如 :38853 或 0.0.0.0:38853）", defaultListenAddr)
	if err != nil {
		return err
	}
	apiHost, err := promptAPIHost(reader)
	if err != nil {
		return err
	}
	listenPort, err := portFromListenAddr(listenAddr)
	if err != nil {
		return errors.New("监听地址无效；端口必须在 1 到 65535 之间，例如 :38853 或 0.0.0.0:38853")
	}

	ports, err := promptPorts(reader, listenPort)
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
	fmt.Printf("\nHTTP 控制端口 TCP %d 将允许连接后验证 Bearer。目标端口 TCP %s 将默认拒绝，只允许白名单来源。\n", listenPort, formatPorts(ports))
	fmt.Println("注意：HTTP 不加密，Bearer Token 会以明文传输；请仅在可信网络或 VPN 中使用。")
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
		APIHost:     apiHost,
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

func promptPorts(reader *bufio.Reader, controlPort int) ([]int, error) {
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

func printCurlCommand(cfg Config) {
	host, portText, err := net.SplitHostPort(cfg.ListenAddr)
	if err != nil {
		fmt.Printf("读取监听地址失败：%v\n", err)
		return
	}
	if cfg.APIHost != "" {
		host = cfg.APIHost
	}
	needsHost := host == "" || host == "0.0.0.0" || host == "::"
	if needsHost {
		host = "YOUR_SERVER_IP_OR_DOMAIN"
	}
	apiURL := "http://" + net.JoinHostPort(host, portText) + "/v1/allow"
	fmt.Printf("API 地址：%s\n", apiURL)
	fmt.Println("从要放行的客户端终端执行下面命令：")
	if needsHost {
		fmt.Println("请先把 YOUR_SERVER_IP_OR_DOMAIN 替换为服务器公网 IP 或域名。")
	}
	fmt.Println("注意：命令包含完整 Token；粘贴到终端可能写入 shell 历史，请勿转发或保存到共享环境。HTTP 会明文传输 Token。")
	fmt.Printf("curl --config - --fail-with-body --request POST %s <<'IP_SELF_CURL'\n", shellQuote(apiURL))
	fmt.Printf("header = \"Authorization: Bearer %s\"\n", cfg.Token)
	fmt.Println("IP_SELF_CURL")
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func updateAPIListenPort(cfg Config, configPath string, reader *bufio.Reader) error {
	if err := requireLinuxRoot(); err != nil {
		return err
	}
	currentPort := configuredControlPort(cfg)
	value, err := prompt(reader, fmt.Sprintf("新的 HTTP API 端口（当前 %d）", currentPort))
	if err != nil {
		return err
	}
	newPort, err := strconv.Atoi(value)
	if err != nil || newPort < 1 || newPort > 65535 {
		return errors.New("端口必须是 1 到 65535 之间的整数")
	}
	if newPort == currentPort {
		return errors.New("新端口与当前端口相同")
	}
	for _, protectedPort := range cfg.TargetPorts {
		if protectedPort == newPort {
			return errors.New("API 监听端口不能同时作为受保护的业务端口")
		}
	}
	if err := ensureAddressAvailable(cfg.ListenAddr); err != nil {
		return fmt.Errorf("%w；请先停止 API 服务后再修改", err)
	}
	host, _, err := net.SplitHostPort(cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("parse current listen address: %w", err)
	}
	newAddress := net.JoinHostPort(host, strconv.Itoa(newPort))
	if err := ensureAddressAvailable(newAddress); err != nil {
		return fmt.Errorf("new listen address is unavailable: %w", err)
	}

	updated := cfg
	updated.ListenAddr = newAddress
	if err := validateConfig(updated); err != nil {
		return err
	}
	if err := saveConfig(configPath, updated); err != nil {
		return err
	}
	if err := firewallSetup(updated); err != nil {
		if rollbackErr := saveConfig(configPath, cfg); rollbackErr != nil {
			return fmt.Errorf("apply new firewall rules: %v; restore old config: %w", err, rollbackErr)
		}
		if rollbackErr := firewallSetup(cfg); rollbackErr != nil {
			return fmt.Errorf("apply new firewall rules: %v; restore old firewall rules: %w", err, rollbackErr)
		}
		return fmt.Errorf("apply new firewall rules: %w", err)
	}
	return nil
}

func ensureAddressAvailable(address string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("%s is already in use or unavailable", address)
	}
	return listener.Close()
}

func promptAPIHost(reader *bufio.Reader) (string, error) {
	for {
		value, err := prompt(reader, "服务器公网 IP/域名（用于生成 curl，可留空后再设置）")
		if err != nil {
			return "", err
		}
		value = strings.TrimSpace(value)
		if validAPIHost(value) {
			return value, nil
		}
		fmt.Println("请输入不带协议、端口或路径的域名/IP，例如 45.202.246.167。")
	}
}

func updateAPIHost(cfg Config, configPath string, reader *bufio.Reader) error {
	value, err := promptAPIHost(reader)
	if err != nil {
		return err
	}
	updated := cfg
	updated.APIHost = value
	return saveConfig(configPath, updated)
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
