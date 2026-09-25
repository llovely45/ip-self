package main

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
)

const iptablesChain = "IPSELF_38853"

func setupIPTables(cfg Config) error {
	if err := refuseIfUFWActive("iptables"); err != nil {
		return err
	}
	for _, family := range []string{"iptables", "ip6tables"} {
		if _, err := exec.LookPath(family); err != nil {
			return fmt.Errorf("%s command not found", family)
		}
		if err := setupIPTablesFamily(family, cfg); err != nil {
			return err
		}
	}
	return nil
}

func setupIPTablesFamily(binary string, cfg Config) error {
	ctx := context.Background()
	all, err := runIPTables(ctx, binary, []string{"-S"})
	if err != nil {
		return err
	}
	chainExists := false
	var managedJumps []protocolPort
	transitionRules := make(map[protocolPort]int)
	for _, line := range strings.Split(all, "\n") {
		line = strings.TrimSpace(line)
		if line == "-N "+iptablesChain {
			chainExists = true
			continue
		}
		if strings.HasPrefix(line, "-A "+iptablesChain+" ") && !strings.Contains(line, "--comment ip-self-managed-") {
			return fmt.Errorf("%s chain %s contains unmanaged rules; refusing to modify it", binary, iptablesChain)
		}
		if !strings.HasPrefix(line, "-A INPUT ") {
			continue
		}
		if strings.Contains(line, "-j "+iptablesChain) {
			target, ok := parseManagedIPTablesJump(line)
			if !ok {
				return fmt.Errorf("%s INPUT has an unmanaged jump to %s; refusing to alter it", binary, iptablesChain)
			}
			managedJumps = append(managedJumps, target)
		}
		if strings.Contains(line, "--comment ip-self-managed-transition") {
			target, parseErr := parseTransitionRule(line)
			if parseErr != nil {
				return fmt.Errorf("%s INPUT contains an invalid ip-self transition rule; refusing to alter it", binary)
			}
			transitionRules[target]++
		}
	}

	// Temporary INPUT drops keep protected protocol/port pairs closed while
	// the dedicated chain and its jumps are rebuilt. If setup fails, they stay.
	targets := configuredPortRules(cfg)
	for _, target := range targets {
		if transitionRules[target] > 0 {
			continue
		}
		args := append([]string{"-I", "INPUT", "1"}, iptablesProtocolArgs(target)...)
		args = append(args, "-m", "comment", "--comment", "ip-self-managed-transition", "-j", "DROP")
		if _, err := runIPTables(ctx, binary, args); err != nil {
			return err
		}
		transitionRules[target]++
	}

	if !chainExists {
		if _, err := runIPTables(ctx, binary, []string{"-N", iptablesChain}); err != nil {
			return err
		}
	}
	if _, err := runIPTables(ctx, binary, []string{"-F", iptablesChain}); err != nil {
		return err
	}

	control := protocolPort{protocol: "tcp", port: configuredControlPort(cfg)}
	args := append([]string{"-A", iptablesChain}, iptablesProtocolArgs(control)...)
	args = append(args, "-m", "comment", "--comment", "ip-self-managed-control", "-j", "ACCEPT")
	if _, err := runIPTables(ctx, binary, args); err != nil {
		return err
	}
	for _, ipText := range sortedIPs(cfg.AllowedIPs) {
		ip, _ := netip.ParseAddr(ipText)
		if (binary == "iptables") != ip.Is4() {
			continue
		}
		for _, target := range targets {
			args := append([]string{"-A", iptablesChain}, iptablesProtocolArgs(target)...)
			args = append(args, "-s", ip.String(), "-m", "comment", "--comment", "ip-self-managed-allow", "-j", "ACCEPT")
			if _, err := runIPTables(ctx, binary, args); err != nil {
				return err
			}
		}
	}
	for _, target := range targets {
		args := append([]string{"-A", iptablesChain}, iptablesProtocolArgs(target)...)
		args = append(args, "-m", "comment", "--comment", "ip-self-managed-deny", "-j", "DROP")
		if _, err := runIPTables(ctx, binary, args); err != nil {
			return err
		}
	}
	if _, err := runIPTables(ctx, binary, []string{"-A", iptablesChain, "-m", "comment", "--comment", "ip-self-managed-return", "-j", "RETURN"}); err != nil {
		return err
	}

	for _, oldTarget := range managedJumps {
		jumpArgs := append(iptablesProtocolArgs(oldTarget), "-m", "comment", "--comment", "ip-self-managed-jump", "-j", iptablesChain)
		args := append([]string{"-D", "INPUT"}, jumpArgs...)
		if _, err := runIPTables(ctx, binary, args); err != nil {
			return err
		}
	}
	jumpTargets := append(append([]protocolPort(nil), targets...), control)
	for _, target := range jumpTargets {
		jumpArgs := append(iptablesProtocolArgs(target), "-m", "comment", "--comment", "ip-self-managed-jump", "-j", iptablesChain)
		args := append([]string{"-I", "INPUT", "1"}, jumpArgs...)
		if _, err := runIPTables(ctx, binary, args); err != nil {
			return err
		}
	}
	for target, count := range transitionRules {
		for range count {
			transitionArgs := append([]string{"-D", "INPUT"}, iptablesProtocolArgs(target)...)
			transitionArgs = append(transitionArgs, "-m", "comment", "--comment", "ip-self-managed-transition", "-j", "DROP")
			if _, err := runIPTables(ctx, binary, transitionArgs); err != nil {
				return err
			}
		}
	}
	return nil
}

func iptablesProtocolArgs(target protocolPort) []string {
	return []string{"-p", target.protocol, "-m", target.protocol, "--dport", strconv.Itoa(target.port)}
}

func parseTransitionRule(rule string) (protocolPort, error) {
	fields := strings.Fields(rule)
	target, ok := parseIPTablesProtocolPort(fields, "INPUT")
	if !ok {
		return protocolPort{}, fmt.Errorf("invalid protocol/port match")
	}
	expected := "-A INPUT " + strings.Join(iptablesProtocolArgs(target), " ") + " -m comment --comment ip-self-managed-transition -j DROP"
	if rule != expected {
		return protocolPort{}, fmt.Errorf("transition rule does not match managed form")
	}
	return target, nil
}

func parseManagedIPTablesJump(rule string) (protocolPort, bool) {
	fields := strings.Fields(strings.TrimSpace(rule))
	target, ok := parseIPTablesProtocolPort(fields, "INPUT")
	if !ok {
		return protocolPort{}, false
	}
	expected := "-A INPUT " + strings.Join(iptablesProtocolArgs(target), " ") + " -m comment --comment ip-self-managed-jump -j " + iptablesChain
	return target, rule == expected
}

func parseIPTablesProtocolPort(fields []string, chain string) (protocolPort, bool) {
	if len(fields) < 8 || fields[0] != "-A" || fields[1] != chain || fields[2] != "-p" {
		return protocolPort{}, false
	}
	protocol := fields[3]
	if (protocol != "tcp" && protocol != "udp") || fields[4] != "-m" || fields[5] != protocol || fields[6] != "--dport" {
		return protocolPort{}, false
	}
	port, err := strconv.Atoi(fields[7])
	if err != nil || port < 1 || port > 65535 {
		return protocolPort{}, false
	}
	return protocolPort{protocol: protocol, port: port}, true
}

func allowIPTables(cfg Config, ip netip.Addr) error {
	if err := refuseIfUFWActive("iptables"); err != nil {
		return err
	}
	binary := "ip6tables"
	if ip.Is4() {
		binary = "iptables"
	}
	if _, err := exec.LookPath(binary); err != nil {
		return fmt.Errorf("%s command not found", binary)
	}
	for _, target := range configuredPortRules(cfg) {
		args := append([]string{"-I", iptablesChain, "1"}, iptablesProtocolArgs(target)...)
		args = append(args, "-s", ip.String(), "-m", "comment", "--comment", "ip-self-managed-allow", "-j", "ACCEPT")
		if _, err := runIPTables(context.Background(), binary, args); err != nil {
			return err
		}
	}
	return nil
}

func runIPTables(ctx context.Context, binary string, args []string) (string, error) {
	args = append([]string{"-w", "5"}, args...)
	return runFirewallCommand(ctx, binary, args, "")
}
