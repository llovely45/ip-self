//go:build !linux

package main

import "errors"

func startBackgroundServer(string) (int, string, error) {
	return 0, "", errors.New("background firewall-managed service is supported on Linux only")
}

func startSystemdAPIService(string) (bool, error) { return false, nil }

func notifyBackgroundReady() error { return nil }
