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
	managedJumpPorts := make([]int, 0, 1)
	transitionPorts := make(map[int]int)
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
			port, ok := parseManagedIPTablesJump(line)
			if !ok {
				return fmt.Errorf("%s INPUT has an unmanaged jump to %s; refusing to alter it", binary, iptablesChain)
			}
			managedJumpPorts = append(managedJumpPorts, port)
		}
		if strings.Contains(line, "--comment ip-self-managed-transition") {
			port, parseErr := parseTransitionPort(line)
			if parseErr != nil {
				return fmt.Errorf("%s INPUT contains an invalid ip-self transition rule; refusing to alter it", binary)
			}
			transitionPorts[port]++
		}
	}

	// Temporary INPUT drops keep protected ports closed while the dedicated
	// chain is rebuilt. If setup fails partway through, these fail-closed rules
	// remain for the operator to retry or remove after inspecting the firewall.
	for _, port := range cfg.TargetPorts {
		if transitionPorts[port] > 0 {
			continue
		}
		args := []string{"-I", "INPUT", "1", "-p", "tcp", "--dport", strconv.Itoa(port), "-m", "comment", "--comment", "ip-self-managed-transition", "-j", "DROP"}
		if _, err := runIPTables(ctx, binary, args); err != nil {
			return err
		}
		transitionPorts[port]++
	}

	if !chainExists {
		if _, err := runIPTables(ctx, binary, []string{"-N", iptablesChain}); err != nil {
			return err
		}
	}
	if _, err := runIPTables(ctx, binary, []string{"-F", iptablesChain}); err != nil {
		return err
	}

	controlPort := configuredControlPort(cfg)
	if _, err := runIPTables(ctx, binary, []string{"-A", iptablesChain, "-p", "tcp", "--dport", fmt.Sprint(controlPort), "-m", "comment", "--comment", "ip-self-managed-control", "-j", "ACCEPT"}); err != nil {
		return err
	}
	for _, ipText := range sortedIPs(cfg.AllowedIPs) {
		ip, _ := netip.ParseAddr(ipText)
		if (binary == "iptables") != ip.Is4() {
			continue
		}
		for _, port := range cfg.TargetPorts {
			args := []string{"-A", iptablesChain, "-p", "tcp", "--dport", fmt.Sprint(port), "-s", ip.String(), "-m", "comment", "--comment", "ip-self-managed-allow", "-j", "ACCEPT"}
			if _, err := runIPTables(ctx, binary, args); err != nil {
				return err
			}
		}
	}
	for _, port := range cfg.TargetPorts {
		args := []string{"-A", iptablesChain, "-p", "tcp", "--dport", fmt.Sprint(port), "-m", "comment", "--comment", "ip-self-managed-deny", "-j", "DROP"}
		if _, err := runIPTables(ctx, binary, args); err != nil {
			return err
		}
	}
	if _, err := runIPTables(ctx, binary, []string{"-A", iptablesChain, "-m", "comment", "--comment", "ip-self-managed-return", "-j", "RETURN"}); err != nil {
		return err
	}

	for _, oldPort := range managedJumpPorts {
		jumpArgs := []string{"-p", "tcp", "--dport", fmt.Sprint(oldPort), "-m", "comment", "--comment", "ip-self-managed-jump", "-j", iptablesChain}
		args := append([]string{"-D", "INPUT"}, jumpArgs...)
		if _, err := runIPTables(ctx, binary, args); err != nil {
			return err
		}
	}
	jumpArgs := []string{"-p", "tcp", "--dport", fmt.Sprint(controlPort), "-m", "comment", "--comment", "ip-self-managed-jump", "-j", iptablesChain}
	args := append([]string{"-I", "INPUT", "1"}, jumpArgs...)
	if _, err := runIPTables(ctx, binary, args); err != nil {
		return err
	}
	for port, count := range transitionPorts {
		for range count {
			transitionArgs := []string{"-D", "INPUT", "-p", "tcp", "--dport", strconv.Itoa(port), "-m", "comment", "--comment", "ip-self-managed-transition", "-j", "DROP"}
			if _, err := runIPTables(ctx, binary, transitionArgs); err != nil {
				return err
			}
		}
	}
	return nil
}

func parseTransitionPort(rule string) (int, error) {
	fields := strings.Fields(rule)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] != "--dport" {
			continue
		}
		port, err := strconv.Atoi(fields[i+1])
		if err != nil || port < 1 || port > 65535 {
			return 0, fmt.Errorf("invalid port")
		}
		expected := fmt.Sprintf("-A INPUT -p tcp -m tcp --dport %d -m comment --comment ip-self-managed-transition -j DROP", port)
		if rule != expected {
			return 0, fmt.Errorf("transition rule does not match managed form")
		}
		return port, nil
	}
	return 0, fmt.Errorf("missing destination port")
}

func parseManagedIPTablesJump(rule string) (int, bool) {
	fields := strings.Fields(strings.TrimSpace(rule))
	if len(fields) != 14 || fields[0] != "-A" || fields[1] != "INPUT" || fields[2] != "-p" || fields[3] != "tcp" || fields[4] != "-m" || fields[5] != "tcp" || fields[6] != "--dport" || fields[8] != "-m" || fields[9] != "comment" || fields[10] != "--comment" || fields[11] != "ip-self-managed-jump" || fields[12] != "-j" || fields[13] != iptablesChain {
		return 0, false
	}
	port, err := strconv.Atoi(fields[7])
	if err != nil || port < 1 || port > 65535 {
		return 0, false
	}
	expected := fmt.Sprintf("-A INPUT -p tcp -m tcp --dport %d -m comment --comment ip-self-managed-jump -j %s", port, iptablesChain)
	return port, rule == expected
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
	for _, port := range cfg.TargetPorts {
		args := []string{"-I", iptablesChain, "1", "-p", "tcp", "--dport", fmt.Sprint(port), "-s", ip.String(), "-m", "comment", "--comment", "ip-self-managed-allow", "-j", "ACCEPT"}
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
