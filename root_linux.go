//go:build linux

package main

import (
	"os"
	"syscall"
)

func osGeteuid() int { return os.Geteuid() }

func secureConfigOwner(info os.FileInfo) bool {
	if os.Geteuid() != 0 {
		return true
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0
}
