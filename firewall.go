package main

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"runtime"
	"strings"
)

func requireLinuxRoot() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("firewall management is supported on Linux only (current OS: %s)", runtime.GOOS)
	}
	if osGeteuid() != 0 {
		return fmt.Errorf("firewall management needs root; run `sudo ip-self`")
	}
	return nil
}

func firewallSetup(cfg Config) error {
	if err := requireLinuxRoot(); err != nil {
		return err
	}
	switch cfg.Firewall {
	case "ufw":
		return setupUFW(cfg)
	case "iptables":
		return setupIPTables(cfg)
	case "nftables":
		return setupNFTables(cfg)
	default:
		return fmt.Errorf("unsupported firewall backend %q", cfg.Firewall)
	}
}

func preflightFirewall(backend string) error {
	if err := requireLinuxRoot(); err != nil {
		return err
	}
	ctx := context.Background()
	switch backend {
	case "ufw":
		if _, err := exec.LookPath("ufw"); err != nil {
			return fmt.Errorf("ufw command not found")
		}
		status, err := runFirewallCommand(ctx, "ufw", []string{"status"}, "")
		if err != nil {
			return err
		}
		if !strings.Contains(strings.ToLower(status), "status: active") {
			return fmt.Errorf("UFW must already be active")
		}
		_, err = runFirewallCommand(ctx, "ufw", []string{"status", "numbered"}, "")
		return err
	case "iptables":
		if err := refuseIfUFWActive("iptables"); err != nil {
			return err
		}
		for _, binary := range []string{"iptables", "ip6tables"} {
			if _, err := exec.LookPath(binary); err != nil {
				return fmt.Errorf("%s command not found", binary)
			}
			if err := preflightIPTablesBinary(ctx, binary); err != nil {
				return err
			}
		}
		return nil
	case "nftables":
		if err := refuseIfUFWActive("nftables"); err != nil {
			return err
		}
		if _, err := exec.LookPath("nft"); err != nil {
			return fmt.Errorf("nft command not found")
		}
		tables, err := runFirewallCommand(ctx, "nft", []string{"list", "tables"}, "")
		if err != nil {
			return err
		}
		for _, line := range strings.Split(tables, "\n") {
			if strings.TrimSpace(line) != "table inet "+nftTableName {
				continue
			}
			current, err := runFirewallCommand(ctx, "nft", []string{"list", "table", "inet", nftTableName}, "")
			if err != nil {
				return err
			}
			return validateOwnedNFTTable(current)
		}
		return nil
	default:
		return fmt.Errorf("unsupported firewall backend %q", backend)
	}
}

func preflightIPTablesBinary(ctx context.Context, binary string) error {
	all, err := runIPTables(ctx, binary, []string{"-S"})
	if err != nil {
		return err
	}
	for _, line := range strings.Split(all, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "-A "+iptablesChain+" ") && !strings.Contains(line, "--comment ip-self-managed-") {
			return fmt.Errorf("%s chain %s contains unmanaged rules; refusing to modify it", binary, iptablesChain)
		}
		if !strings.HasPrefix(line, "-A INPUT ") || !strings.Contains(line, "-j "+iptablesChain) {
			continue
		}
		if _, ok := parseManagedIPTablesJump(line); !ok {
			return fmt.Errorf("%s INPUT has an unmanaged jump to %s; refusing to alter it", binary, iptablesChain)
		}
	}
	return nil
}

func firewallAllow(cfg Config, ip netip.Addr) error {
	if err := requireLinuxRoot(); err != nil {
		return err
	}
	switch cfg.Firewall {
	case "ufw":
		return allowUFW(cfg, ip)
	case "iptables":
		return allowIPTables(cfg, ip)
	case "nftables":
		return allowNFTables(cfg, ip)
	default:
		return fmt.Errorf("unsupported firewall backend %q", cfg.Firewall)
	}
}

func runFirewallCommand(ctx context.Context, name string, args []string, stdin string) (string, error) {
	return runCommand(ctx, name, args, stdin)
}
