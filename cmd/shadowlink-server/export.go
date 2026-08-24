package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/nixavpn/shadowlink/client"
	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/server"
	"gopkg.in/yaml.v3"
)

// runExportClientConfig generates a client config (YAML and/or sl:// URL)
// from the server's private key and user-specified connection parameters.
func runExportClientConfig(args []string) {
	fs := flag.NewFlagSet("export-client-config", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to server YAML config file (required)")
	domain := fs.String("domain", "", "Server domain name for client connections (required)")
	port := fs.String("port", "", "Server port (default: from config listen address, or 443)")
	ws := fs.Bool("ws", true, "Enable WebSocket transport")
	auto := fs.Bool("auto", true, "Enable auto mode (combined TLS+WS)")
	cdn := fs.String("cdn", "", "CDN domain (e.g., cdn.example.com)")
	format := fs.String("format", "both", "Output format: yaml, url, or both")
	output := fs.String("output", "", "Output file path (default: stdout)")
	name := fs.String("name", "", "Connection name (included as YAML comment)")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: shadowlink-server export-client-config [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Generate a client configuration from the server's private key.\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	// Validate required flags.
	if *configPath == "" {
		fmt.Fprintf(os.Stderr, "Error: --config is required\n")
		fs.Usage()
		os.Exit(1)
	}
	if *domain == "" {
		fmt.Fprintf(os.Stderr, "Error: --domain is required\n")
		fs.Usage()
		os.Exit(1)
	}
	if *format != "yaml" && *format != "url" && *format != "both" {
		fmt.Fprintf(os.Stderr, "Error: --format must be yaml, url, or both\n")
		os.Exit(1)
	}

	// Load server config to get the key file path and listen port.
	fc, err := server.LoadConfigFile(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	keyFilePath := fc.ServerKey
	if keyFilePath == "" {
		fmt.Fprintf(os.Stderr, "Error: server_key not set in config file\n")
		os.Exit(1)
	}

	// Read the private key file (hex-encoded string).
	keyData, err := os.ReadFile(keyFilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading server key file %q: %v\n", keyFilePath, err)
		os.Exit(1)
	}
	privHex := strings.TrimSpace(string(keyData))
	privBytes, err := hex.DecodeString(privHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding server key (expected hex): %v\n", err)
		os.Exit(1)
	}

	// Derive public key from private key.
	kp, err := core.KeyPairFromPrivate(privBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deriving public key: %v\n", err)
		os.Exit(1)
	}
	pubHex := hex.EncodeToString(kp.Public)

	// Determine port: explicit flag > config listen address > 443.
	resolvedPort := "443"
	if *port != "" {
		resolvedPort = *port
	} else if fc.Listen != "" {
		if idx := strings.LastIndex(fc.Listen, ":"); idx != -1 {
			p := fc.Listen[idx+1:]
			if p != "" {
				resolvedPort = p
			}
		}
	}

	// Build client config.
	cfg := &client.ClientFileConfig{
		Server:    *domain + ":" + resolvedPort,
		PubKey:    pubHex,
		TLS:       true,
		WebSocket: *ws,
		Auto:      *auto,
		CDN:       *cdn,
	}

	// Prepare output.
	var out strings.Builder

	if *format == "yaml" || *format == "both" {
		if *name != "" {
			out.WriteString(fmt.Sprintf("# %s\n", *name))
		}
		yamlBytes, err := yaml.Marshal(cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling YAML: %v\n", err)
			os.Exit(1)
		}
		out.Write(yamlBytes)
	}

	if *format == "both" {
		out.WriteString("\n---\n\n")
	}

	if *format == "url" || *format == "both" {
		slURL := client.BuildSLURL(cfg)
		out.WriteString(slURL)
		out.WriteString("\n")
	}

	// Write output.
	if *output != "" {
		if err := os.WriteFile(*output, []byte(out.String()), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output file: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Client config written to %s\n", *output)
	} else {
		fmt.Print(out.String())
	}
}
