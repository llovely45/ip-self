//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const backgroundReadyEnv = "IP_SELF_BACKGROUND_CHILD"

func startBackgroundServer(configPath string) (int, string, error) {
	if err := requireLinuxRoot(); err != nil {
		return 0, "", err
	}

	absConfigPath, err := filepath.Abs(configPath)
	if err != nil {
		return 0, "", fmt.Errorf("resolve configuration path: %w", err)
	}
	if _, err := loadConfig(absConfigPath); err != nil {
		return 0, "", fmt.Errorf("load configuration: %w", err)
	}
	logPath := filepath.Join(filepath.Dir(absConfigPath), "ip-self.log")
	logFile, err := openBackgroundLog(logPath)
	if err != nil {
		return 0, "", err
	}
	defer logFile.Close()

	executable, err := os.Executable()
	if err != nil {
		return 0, "", fmt.Errorf("locate ip-self executable: %w", err)
	}
	if resolved, resolveErr := filepath.EvalSymlinks(executable); resolveErr == nil {
		executable = resolved
	}

	readReady, writeReady, err := os.Pipe()
	if err != nil {
		return 0, "", fmt.Errorf("create API startup channel: %w", err)
	}
	defer readReady.Close()
	cmd := exec.Command(executable, "serve", "--config", absConfigPath)
	cmd.Stdin = nil
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.ExtraFiles = []*os.File{writeReady}
	cmd.Env = append(os.Environ(), backgroundReadyEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		writeReady.Close()
		return 0, "", fmt.Errorf("start API process: %w", err)
	}
	_ = writeReady.Close()
	_ = logFile.Close()

	ready := make(chan error, 1)
	go func() {
		var signal [1]byte
		_, readErr := io.ReadFull(readReady, signal[:])
		if readErr != nil {
			ready <- readErr
			return
		}
		if signal[0] != 1 {
			ready <- errors.New("child returned an invalid startup signal")
			return
		}
		ready <- nil
	}()

	startupTimeout := time.NewTimer(15 * time.Second)
	defer startupTimeout.Stop()
	select {
	case readyErr := <-ready:
		if readyErr != nil {
			waitErr := cmd.Wait()
			if waitErr == nil {
				waitErr = readyErr
			}
			return 0, "", fmt.Errorf("API process exited before becoming ready (%v); startup log: %s", waitErr, backgroundLogTail(logPath))
		}
		// The child is detached and has completed all startup checks. Release the
		// parent's process handle; the child remains managed by the OS.
		_ = cmd.Process.Release()
		return cmd.Process.Pid, logPath, nil
	case <-startupTimeout.C:
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return 0, "", fmt.Errorf("API process did not become ready within 15 seconds; startup log: %s", backgroundLogTail(logPath))
	}
}

func openBackgroundLog(path string) (*os.File, error) {
	if err := validateConfigDirectory(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("log directory is not secure: %w", err)
	}
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_APPEND|syscall.O_WRONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("open service log: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("inspect service log: %w", err)
	}
	if !info.Mode().IsRegular() || !secureConfigOwner(info) {
		file.Close()
		return nil, errors.New("service log must be a regular file owned by root")
	}
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return nil, fmt.Errorf("restrict service log permissions: %w", err)
	}
	return file, nil
}

func backgroundLogTail(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return "log unavailable"
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "log unavailable"
	}
	const maxTail = 4096
	start := info.Size() - maxTail
	if start < 0 {
		start = 0
	}
	data := make([]byte, info.Size()-start)
	if _, err := file.ReadAt(data, start); err != nil && !errors.Is(err, io.EOF) {
		return "log unavailable"
	}
	return strings.TrimSpace(string(data))
}

func notifyBackgroundReady() error {
	if os.Getenv(backgroundReadyEnv) != "1" {
		return nil
	}
	readyPipe := os.NewFile(3, "ip-self-startup-notify")
	if readyPipe == nil {
		return errors.New("startup notification pipe is unavailable")
	}
	defer readyPipe.Close()
	if _, err := readyPipe.Write([]byte{1}); err != nil {
		return err
	}
	return nil
}
