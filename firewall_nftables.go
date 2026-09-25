package main

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

const nftTableName = "ipself"

func setupNFTables(cfg Config) error {
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("nft command not found")
	}
	if err := refuseIfUFWActive("nftables"); err != nil {
		return err
	}
	ctx := context.Background()
	tables, err := runFirewallCommand(ctx, "nft", []string{"list", "tables"}, "")
	if err != nil {
		return err
	}
	exists := false
	for _, line := range strings.Split(tables, "\n") {
		if strings.TrimSpace(line) == "table inet "+nftTableName {
			exists = true
		}
	}
	var script strings.Builder
	if exists {
		current, err := runFirewallCommand(ctx, "nft", []string{"list", "table", "inet", nftTableName}, "")
		if err != nil {
			return err
		}
		if err := validateOwnedNFTTable(current); err != nil {
			return err
		}
		script.WriteString("delete table inet " + nftTableName + "\n")
	}
	script.WriteString(renderNFTTable(cfg))
	if _, err := runFirewallCommand(ctx, "nft", []string{"-f", "-"}, script.String()); err != nil {
		return err
	}
	return nil
}

func validateOwnedNFTTable(current string) error {
	insideChain := false
	ownedRule := false
	for _, line := range strings.Split(current, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "set ") && !strings.HasPrefix(trimmed, "set allow4 ") && !strings.HasPrefix(trimmed, "set allow6 ") {
			return fmt.Errorf("nftables table inet %s contains an unmanaged set; refusing to replace it", nftTableName)
		}
		if strings.HasPrefix(trimmed, "chain ") {
			if !strings.HasPrefix(trimmed, "chain input ") {
				return fmt.Errorf("nftables table inet %s contains an unmanaged chain; refusing to replace it", nftTableName)
			}
			insideChain = true
			continue
		}
		if !insideChain || trimmed == "" || trimmed == "}" || strings.HasPrefix(trimmed, "type ") {
			if trimmed == "}" {
				insideChain = false
			}
			continue
		}
		if !strings.Contains(trimmed, `comment "ip-self-managed-`) {
			return fmt.Errorf("nftables table inet %s contains an unmanaged rule; refusing to replace it", nftTableName)
		}
		ownedRule = true
	}
	if !ownedRule {
		return fmt.Errorf("nftables table inet %s has no ip-self ownership rule; refusing to replace it", nftTableName)
	}
	return nil
}

func renderNFTTable(cfg Config) string {
	var out strings.Builder
	out.WriteString("table inet " + nftTableName + " {\n")
	out.WriteString("  set allow4 { type ipv4_addr; flags interval;\n")
	var v4, v6 []string
	for _, text := range sortedIPs(cfg.AllowedIPs) {
		ip, _ := netip.ParseAddr(text)
		if ip.Is4() {
			v4 = append(v4, ip.String())
		} else {
			v6 = append(v6, ip.String())
		}
	}
	if len(v4) > 0 {
		out.WriteString("    elements = { " + strings.Join(v4, ", ") + " }\n")
	}
	out.WriteString("  }\n")
	out.WriteString("  set allow6 { type ipv6_addr; flags interval;\n")
	if len(v6) > 0 {
		out.WriteString("    elements = { " + strings.Join(v6, ", ") + " }\n")
	}
	out.WriteString("  }\n")
	out.WriteString("  chain input { type filter hook input priority -10; policy accept;\n")
	fmt.Fprintf(&out, "    tcp dport %d counter accept comment \"ip-self-managed-control\"\n", controlPort)
	for _, port := range cfg.TargetPorts {
		fmt.Fprintf(&out, "    tcp dport %d ip saddr @allow4 counter accept comment \"ip-self-managed-allow\"\n", port)
		fmt.Fprintf(&out, "    tcp dport %d ip6 saddr @allow6 counter accept comment \"ip-self-managed-allow\"\n", port)
		fmt.Fprintf(&out, "    tcp dport %d counter drop comment \"ip-self-managed-deny\"\n", port)
	}
	out.WriteString("  }\n")
	out.WriteString("}\n")
	return out.String()
}

func allowNFTables(cfg Config, ip netip.Addr) error {
	if err := refuseIfUFWActive("nftables"); err != nil {
		return err
	}
	set := "allow6"
	if ip.Is4() {
		set = "allow4"
	}
	args := []string{"add", "element", "inet", nftTableName, set, "{", ip.String(), "}"}
	if _, err := runFirewallCommand(context.Background(), "nft", args, ""); err != nil {
		return err
	}
	return nil
}
