package main

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	ufwManagedMarker     = "ip-self-owned:"
	ufwGuardComment      = "ip-self-owned:target-deny"
	ufwTransitionComment = "ip-self-owned:transition"
	ufwControlComment    = "ip-self-owned:control"
	ufwAllowComment      = "ip-self-owned:allow"
)

var ufwRuleNumber = regexp.MustCompile(`^\[\s*([0-9]+)\s*\]`)

func setupUFW(cfg Config) error {
	if _, err := exec.LookPath("ufw"); err != nil {
		return fmt.Errorf("ufw command not found")
	}
	ctx := context.Background()
	status, err := runFirewallCommand(ctx, "ufw", []string{"status"}, "")
	if err != nil {
		return err
	}
	if !strings.Contains(strings.ToLower(status), "status: active") {
		return fmt.Errorf("UFW is not active; ip-self will not enable it automatically to avoid changing host-wide firewall state")
	}
	if err := ensureUFWTransitions(ctx, cfg); err != nil {
		return err
	}
	if err := removeManagedUFWRules(ctx); err != nil {
		return err
	}
	for _, port := range cfg.TargetPorts {
		if _, err := runFirewallCommand(ctx, "ufw", []string{"insert", "1", "deny", fmt.Sprintf("%d/tcp", port), "comment", ufwGuardComment}, ""); err != nil {
			return err
		}
	}
	if _, err := runFirewallCommand(ctx, "ufw", []string{"insert", "1", "allow", fmt.Sprintf("%d/tcp", configuredControlPort(cfg)), "comment", ufwControlComment}, ""); err != nil {
		return err
	}
	for _, ipText := range sortedIPs(cfg.AllowedIPs) {
		ip, _ := netip.ParseAddr(ipText)
		if err := applyUFWAllow(ctx, cfg, ip); err != nil {
			return err
		}
	}
	return removeUFWTransitions(ctx)
}

func refuseIfUFWActive(selected string) error {
	if _, err := exec.LookPath("ufw"); err != nil {
		return nil
	}
	status, err := runFirewallCommand(context.Background(), "ufw", []string{"status"}, "")
	if err != nil {
		return err
	}
	if strings.Contains(strings.ToLower(status), "status: active") {
		return fmt.Errorf("UFW is active; choose the UFW backend instead of changing rules through %s", selected)
	}
	return nil
}

func ensureUFWTransitions(ctx context.Context, cfg Config) error {
	status, err := runFirewallCommand(ctx, "ufw", []string{"status", "numbered"}, "")
	if err != nil {
		return err
	}
	for _, port := range cfg.TargetPorts {
		found := false
		for _, line := range strings.Split(status, "\n") {
			if !strings.Contains(line, ufwTransitionComment) {
				continue
			}
			for _, field := range strings.Fields(line) {
				if field == fmt.Sprintf("%d/tcp", port) {
					found = true
				}
			}
		}
		if !found {
			args := []string{"insert", "1", "deny", fmt.Sprintf("%d/tcp", port), "comment", ufwTransitionComment}
			if _, err := runFirewallCommand(ctx, "ufw", args, ""); err != nil {
				return err
			}
		}
	}
	return nil
}

func removeManagedUFWRules(ctx context.Context) error {
	status, err := runFirewallCommand(ctx, "ufw", []string{"status", "numbered"}, "")
	if err != nil {
		return err
	}
	var numbers []int
	for _, line := range strings.Split(status, "\n") {
		if !strings.Contains(line, ufwManagedMarker) || strings.Contains(line, ufwTransitionComment) {
			continue
		}
		match := ufwRuleNumber.FindStringSubmatch(strings.TrimSpace(line))
		if len(match) != 2 {
			return fmt.Errorf("could not safely identify an ip-self UFW rule")
		}
		n, _ := strconv.Atoi(match[1])
		numbers = append(numbers, n)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(numbers)))
	for _, n := range numbers {
		if _, err := runFirewallCommand(ctx, "ufw", []string{"--force", "delete", strconv.Itoa(n)}, ""); err != nil {
			return err
		}
	}
	return nil
}

func removeUFWTransitions(ctx context.Context) error {
	status, err := runFirewallCommand(ctx, "ufw", []string{"status", "numbered"}, "")
	if err != nil {
		return err
	}
	var numbers []int
	for _, line := range strings.Split(status, "\n") {
		if !strings.Contains(line, ufwTransitionComment) {
			continue
		}
		match := ufwRuleNumber.FindStringSubmatch(strings.TrimSpace(line))
		if len(match) != 2 {
			return fmt.Errorf("could not safely identify an ip-self transition UFW rule")
		}
		n, _ := strconv.Atoi(match[1])
		numbers = append(numbers, n)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(numbers)))
	for _, n := range numbers {
		if _, err := runFirewallCommand(ctx, "ufw", []string{"--force", "delete", strconv.Itoa(n)}, ""); err != nil {
			return err
		}
	}
	return nil
}

func allowUFW(cfg Config, ip netip.Addr) error {
	status, err := runFirewallCommand(context.Background(), "ufw", []string{"status"}, "")
	if err != nil {
		return err
	}
	if !strings.Contains(strings.ToLower(status), "status: active") {
		return fmt.Errorf("UFW is not active; refusing to report an allow rule as effective")
	}
	return applyUFWAllow(context.Background(), cfg, ip)
}

func applyUFWAllow(ctx context.Context, cfg Config, ip netip.Addr) error {
	for _, port := range cfg.TargetPorts {
		args := []string{"insert", "1", "allow", "from", ip.String(), "to", "any", "port", strconv.Itoa(port), "proto", "tcp", "comment", ufwAllowComment}
		if _, err := runFirewallCommand(ctx, "ufw", args, ""); err != nil {
			return err
		}
	}
	return nil
}
