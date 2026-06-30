package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// NginxCert represents an SSL certificate configured in nginx
type NginxCert struct {
	ServerName string   `json:"server_name"`
	CertPath   string   `json:"cert_path"`
	KeyPath    string   `json:"key_path"`
	ConfigFile string   `json:"config_file"`
	LineNo     int      `json:"line_no"`
	Domains    []string `json:"domains"`
}

// FindNginxCerts parses nginx config and returns all SSL certificates in use
func FindNginxCerts() ([]NginxCert, error) {
	// Find main nginx config
	configPaths := []string{
		"/etc/nginx/nginx.conf",
		"/usr/local/nginx/conf/nginx.conf",
		"/opt/homebrew/etc/nginx/nginx.conf",
	}

	var mainConfig string
	for _, p := range configPaths {
		if _, err := os.Stat(p); err == nil {
			mainConfig = p
			break
		}
	}

	if mainConfig == "" {
		return nil, fmt.Errorf("nginx config not found")
	}

	// Collect all config files via include directives
	files := collectNginxFiles(mainConfig)

	var certs []NginxCert
	for _, f := range files {
		certs = append(certs, parseNginxServerBlocks(f)...)
	}

	return certs, nil
}

// collectNginxFiles resolves include directives and returns all config file paths
func collectNginxFiles(mainConfig string) []string {
	var files []string
	seen := map[string]bool{}
	configDir := filepath.Dir(mainConfig)

	var walk func(path string)
	walk = func(path string) {
		if seen[path] {
			return
		}
		seen[path] = true

		// Check for glob patterns
		if strings.Contains(path, "*") {
			matches, err := filepath.Glob(path)
			if err != nil {
				return
			}
			for _, m := range matches {
				walk(m)
			}
			return
		}

		f, err := os.Open(path)
		if err != nil {
			return
		}
		defer f.Close()

		files = append(files, path)

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "#") {
				continue
			}
			if strings.HasPrefix(line, "include ") {
				incPath := strings.TrimPrefix(line, "include ")
				incPath = strings.TrimSpace(incPath)
				incPath = strings.Trim(incPath, ";")
				// Resolve relative paths
				if !filepath.IsAbs(incPath) {
					incPath = filepath.Join(configDir, incPath)
				}
				walk(incPath)
			}
		}
	}

	walk(mainConfig)
	return files
}

// parseNginxServerBlocks extracts SSL certificate info from an nginx config file
func parseNginxServerBlocks(configFile string) []NginxCert {
	f, err := os.Open(configFile)
	if err != nil {
		return nil
	}
	defer f.Close()

	var certs []NginxCert
	scanner := bufio.NewScanner(f)

	var (
		inServer   bool
		hasSSL     bool
		serverName string
		certPath   string
		keyPath    string
		braceDepth int
		lineNo     int
	)

	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Track server block
		if strings.HasPrefix(line, "server ") || line == "server" || strings.HasPrefix(line, "server{") {
			inServer = true
			hasSSL = false
			serverName = ""
			certPath = ""
			keyPath = ""
			braceDepth = 0
		}

		if !inServer {
			continue
		}

		// Count braces
		for _, ch := range line {
			if ch == '{' {
				braceDepth++
			} else if ch == '}' {
				braceDepth--
			}
		}

		// Detect SSL
		if strings.Contains(line, "listen") && (strings.Contains(line, "443") || strings.Contains(line, "ssl")) {
			hasSSL = true
		}

		// Extract server_name
		if strings.HasPrefix(line, "server_name ") {
			serverName = strings.TrimPrefix(line, "server_name ")
			serverName = strings.Trim(serverName, ";")
			serverName = strings.TrimSpace(serverName)
		}

		// Extract ssl_certificate
		if strings.HasPrefix(line, "ssl_certificate ") && !strings.Contains(line, "_key") {
			certPath = strings.TrimPrefix(line, "ssl_certificate ")
			certPath = strings.Trim(certPath, ";")
			certPath = strings.TrimSpace(certPath)
		}

		// Extract ssl_certificate_key
		if strings.HasPrefix(line, "ssl_certificate_key ") {
			keyPath = strings.TrimPrefix(line, "ssl_certificate_key ")
			keyPath = strings.Trim(keyPath, ";")
			keyPath = strings.TrimSpace(keyPath)
		}

		// Server block ends
		if braceDepth <= 0 && inServer {
			if hasSSL && certPath != "" {
				domains := strings.Fields(serverName)
				if len(domains) == 0 && serverName != "" {
					domains = []string{serverName}
				}
				certs = append(certs, NginxCert{
					ServerName: serverName,
					CertPath:   certPath,
					KeyPath:    keyPath,
					ConfigFile: configFile,
					LineNo:     lineNo,
					Domains:    domains,
				})
			}
			inServer = false
		}
	}

	return certs
}

// IsNginxInstalled checks if nginx binary is available
func IsNginxInstalled() bool {
	paths := []string{
		"/usr/sbin/nginx",
		"/usr/bin/nginx",
		"/usr/local/bin/nginx",
		"/opt/homebrew/bin/nginx",
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// ReloadNginx tests and reloads nginx configuration
func ReloadNginx() error {
	// Test config first
	cmd := exec.Command("nginx", "-t")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nginx config test failed: %w", err)
	}
	// Reload
	cmd = exec.Command("nginx", "-s", "reload")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nginx reload failed: %w", err)
	}
	return nil
}
