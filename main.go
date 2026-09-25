package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

var version = "dev"

func main() {
	args, configPath, err := extractConfigPath(os.Args[1:])
	if err != nil {
		fatal(err)
	}
	if configPath == "" {
		configPath = defaultConfigPath()
	}
	command := ""
	if len(args) > 0 {
		command = args[0]
		args = args[1:]
	}
	if len(args) > 0 {
		fatal(fmt.Errorf("unexpected arguments: %s", strings.Join(args, " ")))
	}

	switch command {
	case "", "panel":
		err = runPanel(configPath)
	case "init":
		err = initialize(configPath)
	case "serve":
		var cfg Config
		cfg, err = loadConfig(configPath)
		if err == nil {
			err = persistConfigMigration(configPath, &cfg)
		}
		if err == nil {
			err = serve(cfg, configPath)
		}
	case "firewall":
		if len(args) != 0 {
			fatal(errors.New("usage: ip-self firewall"))
		}
		var cfg Config
		cfg, err = loadConfig(configPath)
		if err == nil {
			err = persistConfigMigration(configPath, &cfg)
		}
		if err == nil {
			err = firewallSetup(cfg)
		}
	case "token":
		var cfg Config
		cfg, err = loadConfig(configPath)
		if err == nil {
			fmt.Println(cfg.Token)
		}
	case "status":
		var cfg Config
		cfg, err = loadConfig(configPath)
		if err == nil {
			printStatus(cfg, configPath)
		}
	case "version", "--version", "-version":
		fmt.Println(version)
	case "help", "--help", "-h":
		printUsage()
	default:
		printUsage()
		err = fmt.Errorf("unknown command %q", command)
	}
	if err != nil {
		fatal(err)
	}
}

func extractConfigPath(args []string) ([]string, string, error) {
	var remaining []string
	path := ""
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--config" || arg == "-config" {
			if i+1 >= len(args) {
				return nil, "", errors.New("--config needs a path")
			}
			i++
			path = args[i]
			continue
		}
		if strings.HasPrefix(arg, "--config=") || strings.HasPrefix(arg, "-config=") {
			path = strings.SplitN(arg, "=", 2)[1]
			if path == "" {
				return nil, "", errors.New("--config needs a path")
			}
			continue
		}
		remaining = append(remaining, arg)
	}
	return remaining, path, nil
}

func printUsage() {
	fmt.Println(`ip-self - token-authenticated IP allowlist controller

Usage:
  ip-self [--config PATH]             Open the interactive panel
  ip-self init [--config PATH]        Create the fixed UUIDv7 token and firewall config
  ip-self serve [--config PATH]       Start the HTTP control API
  ip-self firewall [--config PATH]   Reapply the managed firewall rules
  ip-self token [--config PATH]      Print the token
  ip-self status [--config PATH]     Show configuration status
  ip-self version`)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "ip-self:", err)
	os.Exit(1)
}
