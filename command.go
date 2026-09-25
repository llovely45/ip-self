package main

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

func runCommand(ctx context.Context, name string, args []string, stdin string) (string, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		message := strings.TrimSpace(output.String())
		if len(message) > 800 {
			message = message[:800]
		}
		if message != "" {
			return output.String(), fmt.Errorf("%s failed: %s", name, message)
		}
		return output.String(), fmt.Errorf("%s failed: %w", name, err)
	}
	return output.String(), nil
}
