//go:build !linux

package main

import "os"

func osGeteuid() int                     { return -1 }
func secureConfigOwner(os.FileInfo) bool { return true }
