package main

import (
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type allowServer struct {
	mu             sync.Mutex
	cfg            Config
	configPath     string
	failures       *requestLimiter
	successfulAdds *requestLimiter
}

type requestLimiter struct {
	mu        sync.Mutex
	entries   map[string]limitEntry
	limit     int
	window    time.Duration
	lastSweep time.Time
}

type limitEntry struct {
	start time.Time
	count int
}

func newRequestLimiter(limit int, window time.Duration) *requestLimiter {
	return &requestLimiter{entries: make(map[string]limitEntry), limit: limit, window: window}
}

func (l *requestLimiter) allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) > 4096 && now.Sub(l.lastSweep) >= l.window {
		for entryKey, value := range l.entries {
			if now.Sub(value.start) >= l.window {
				delete(l.entries, entryKey)
			}
		}
		l.lastSweep = now
	}
	entry := l.entries[key]
	if now.Sub(entry.start) >= l.window {
		entry = limitEntry{start: now}
	}
	if entry.count >= l.limit {
		return false
	}
	entry.count++
	l.entries[key] = entry
	if len(l.entries) > 8192 {
		for entryKey := range l.entries {
			if entryKey != key {
				delete(l.entries, entryKey)
				break
			}
		}
	}
	return true
}

func serve(cfg Config, configPath string) error {
	if err := validateConfig(cfg); err != nil {
		return err
	}
	if cfg.TLSCertFile != "" {
		if _, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil {
			return fmt.Errorf("load TLS certificate and key: %w", err)
		}
		if info, err := os.Stat(cfg.TLSKeyFile); err != nil {
			return fmt.Errorf("inspect TLS private key: %w", err)
		} else if info.Mode().Perm()&0077 != 0 {
			return errors.New("TLS private key permissions are too broad; restrict it to owner access (for example chmod 600)")
		}
	} else if !isLoopbackListener(cfg.ListenAddr) {
		return errors.New("TLS certificate and key are required for a non-loopback listener")
	}
	state := &allowServer{
		cfg:            cfg,
		configPath:     configPath,
		failures:       newRequestLimiter(5, time.Minute),
		successfulAdds: newRequestLimiter(20, time.Minute),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/allow", state.handleAllow)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, apiResponse{OK: false, Error: "not found"})
	})
	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      90 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    4096,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	var activeConnections atomic.Int64
	server.ConnState = func(conn net.Conn, state http.ConnState) {
		switch state {
		case http.StateNew:
			if activeConnections.Add(1) > 512 {
				_ = conn.Close()
			}
		case http.StateClosed, http.StateHijacked:
			activeConnections.Add(-1)
		}
	}
	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.ListenAddr, err)
	}
	if err := firewallSetup(cfg); err != nil {
		listener.Close()
		return fmt.Errorf("install firewall rules: %w", err)
	}
	if cfg.TLSCertFile != "" {
		certificate, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			listener.Close()
			return fmt.Errorf("load TLS certificate and key: %w", err)
		}
		server.TLSConfig.Certificates = []tls.Certificate{certificate}
		listener = tls.NewListener(listener, server.TLSConfig)
	}
	fmt.Fprintf(os.Stderr, "ip-self listening on %s; protected TCP ports: %s\n", cfg.ListenAddr, formatPorts(cfg.TargetPorts))
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *allowServer) handleAllow(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w, r)
	if r.URL.Path != "/v1/allow" {
		writeJSON(w, http.StatusNotFound, apiResponse{OK: false, Error: "not found"})
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{OK: false, Error: "method not allowed"})
		return
	}
	if r.URL.RawQuery != "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{OK: false, Error: "query parameters are not accepted"})
		return
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		r.Close = true
		writeJSON(w, http.StatusBadRequest, apiResponse{OK: false, Error: "request body must be empty"})
		return
	}
	ip, err := remoteIP(r.RemoteAddr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{OK: false, Error: "could not determine direct peer IP"})
		return
	}
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		if !s.failures.allow(ip.String()) {
			w.Header().Set("Retry-After", "60")
			writeJSON(w, http.StatusTooManyRequests, apiResponse{OK: false, Error: "rate limit exceeded"})
			return
		}
		writeJSON(w, http.StatusUnauthorized, apiResponse{OK: false, Error: "unauthorized"})
		return
	}
	candidate := strings.TrimPrefix(values[0], "Bearer ")
	s.mu.Lock()
	token := s.cfg.Token
	s.mu.Unlock()
	if subtle.ConstantTimeCompare([]byte(candidate), []byte(token)) != 1 {
		if !s.failures.allow(ip.String()) {
			w.Header().Set("Retry-After", "60")
			writeJSON(w, http.StatusTooManyRequests, apiResponse{OK: false, Error: "rate limit exceeded"})
			return
		}
		writeJSON(w, http.StatusUnauthorized, apiResponse{OK: false, Error: "unauthorized"})
		return
	}
	if !s.successfulAdds.allow(ip.String()) {
		w.Header().Set("Retry-After", "60")
		writeJSON(w, http.StatusTooManyRequests, apiResponse{OK: false, Error: "rate limit exceeded"})
		return
	}

	added, err := s.addIP(ip)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ip-self firewall update failed for %s: %v\n", ip, err)
		writeJSON(w, http.StatusInternalServerError, apiResponse{OK: false, Error: "firewall update failed"})
		return
	}
	status := "already_allowed"
	if added {
		status = "allowed"
	}
	writeJSON(w, http.StatusOK, apiResponse{OK: true, Status: status, IP: ip.String(), Ports: append([]int(nil), s.cfg.TargetPorts...)})
}

func (s *allowServer) addIP(ip netip.Addr) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, current := range s.cfg.AllowedIPs {
		if current == ip.String() {
			return false, nil
		}
	}
	if len(s.cfg.AllowedIPs) >= maxAllowedIPs {
		return false, fmt.Errorf("allowlist limit reached")
	}
	old := s.cfg
	next := old
	next.AllowedIPs = append(append([]string(nil), old.AllowedIPs...), ip.String())
	next.AllowedIPs = sortedIPs(next.AllowedIPs)
	if len(next.AllowedIPs)*len(next.TargetPorts) > maxManagedAllowRules {
		return false, fmt.Errorf("managed firewall rule limit reached")
	}
	if err := saveConfig(s.configPath, next); err != nil {
		return false, err
	}
	if err := firewallAllow(next, ip); err != nil {
		rollbackErr := saveConfig(s.configPath, old)
		if rollbackErr == nil {
			rollbackErr = firewallSetup(old)
		}
		if rollbackErr != nil {
			return false, fmt.Errorf("apply allow rule: %v; rollback failed: %v", err, rollbackErr)
		}
		return false, err
	}
	s.cfg = next
	return true, nil
}

type apiResponse struct {
	OK     bool   `json:"ok"`
	Status string `json:"status,omitempty"`
	IP     string `json:"ip,omitempty"`
	Ports  []int  `json:"ports,omitempty"`
	Error  string `json:"error,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, body apiResponse) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func setSecurityHeaders(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.TLS != nil {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	}
}

func remoteIP(remote string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return netip.Addr{}, err
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, err
	}
	addr = addr.WithZone("").Unmap()
	if !addr.IsGlobalUnicast() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return netip.Addr{}, errors.New("peer IP is not a routable unicast address")
	}
	return addr, nil
}

func parseClientIP(value string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, err
	}
	addr = addr.WithZone("").Unmap()
	if !addr.IsGlobalUnicast() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return netip.Addr{}, errors.New("IP is not a routable unicast address")
	}
	return addr, nil
}

func isLoopbackListener(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

func formatPorts(ports []int) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, fmt.Sprint(p))
	}
	return strings.Join(parts, ",")
}
