package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CertInfo holds parsed certificate information
type CertInfo struct {
	Subject  string    `json:"subject"`
	DNSNames []string  `json:"dns_names"`
	NotAfter time.Time `json:"not_after"`
	DaysLeft int       `json:"days_left"`
	Expired  bool      `json:"expired"`
	Issuer   string    `json:"issuer"`
}

// LoadCertFromFile reads and parses a certificate file
func LoadCertFromFile(path string) (*CertInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read cert file: %w", err)
	}
	return ParseCert(data)
}

// LoadCertFromDomain connects to a domain and retrieves its certificate
func LoadCertFromDomain(domain string, timeout time.Duration) (*CertInfo, error) {
	if !strings.Contains(domain, ":") {
		domain = domain + ":443"
	}

	conn, err := tls.Dial("tcp", domain, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", domain, err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	return certToInfo(certs[0]), nil
}

// ParseCert parses PEM-encoded certificate data
func ParseCert(data []byte) (*CertInfo, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	return certToInfo(cert), nil
}

func certToInfo(cert *x509.Certificate) *CertInfo {
	now := time.Now()
	daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)

	return &CertInfo{
		Subject:  cert.Subject.CommonName,
		DNSNames: cert.DNSNames,
		NotAfter: cert.NotAfter,
		DaysLeft: daysLeft,
		Expired:  daysLeft < 0,
		Issuer:   cert.Issuer.CommonName,
	}
}

// StatusEmoji returns emoji based on days remaining
func (c *CertInfo) StatusEmoji(threshold int) string {
	if c.Expired {
		return "❌"
	}
	if c.DaysLeft <= 7 {
		return "🔴"
	}
	if c.DaysLeft <= threshold {
		return "⚠️"
	}
	return "✅"
}

// CertFile represents a certificate file found in nginx config
type CertFile struct {
	Path    string   `json:"path"`
	Domains []string `json:"domains"`
	KeyPath string   `json:"key_path"`
}

// FindCertFiles walks a directory tree looking for .pem/.crt/.cer files
func FindCertFiles(root string) ([]CertFile, error) {
	var certs []CertFile
	seen := make(map[string]bool)

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip inaccessible
		}
		if info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".pem" && ext != ".crt" && ext != ".cer" {
			return nil
		}
		if seen[path] {
			return nil
		}
		seen[path] = true

		ci, err := LoadCertFromFile(path)
		if err != nil {
			return nil // not a valid cert
		}

		domains := ci.DNSNames
		if ci.Subject != "" && !contains(domains, ci.Subject) {
			domains = append([]string{ci.Subject}, domains...)
		}

		certs = append(certs, CertFile{
			Path:    path,
			Domains: domains,
		})
		return nil
	})

	return certs, err
}

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}
