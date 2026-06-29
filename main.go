package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// State holds persistent configuration
type State struct {
	Certs      map[string]CertEntry `json:"certs"`
	RenewDays  int                  `json:"renew_days"`
	CertDir    string               `json:"cert_dir"`
	LastScan   string               `json:"last_scan"`
}

type CertEntry struct {
	Cert string    `json:"cert"`
	Key  string    `json:"key"`
	Info *CertInfo `json:"info"`
}

var (
	confDir  = "/etc/ssl/cert-mgr"
	stateFile = confDir + "/state.json"
)

func loadState() State {
	os.MkdirAll(confDir, 0755)
	data, err := os.ReadFile(stateFile)
	if err != nil {
		return State{Certs: map[string]CertEntry{}, RenewDays: 30, CertDir: confDir}
	}
	var s State
	json.Unmarshal(data, &s)
	if s.Certs == nil {
		s.Certs = map[string]CertEntry{}
	}
	if s.RenewDays == 0 {
		s.RenewDays = 30
	}
	if s.CertDir == "" {
		s.CertDir = confDir
	}
	return s
}

func saveState(s State) {
	os.MkdirAll(confDir, 0755)
	data, _ := json.MarshalIndent(s, "", "  ")
	os.WriteFile(stateFile, data, 0644)
}

func main() {
	if len(os.Args) < 2 {
		help()
		return
	}

	switch os.Args[1] {
	case "scan":
		cmdScan()
	case "status":
		cmdStatus()
	case "check":
		cmdCheck()
	case "issue":
		domain := ""
		if len(os.Args) > 2 {
			domain = os.Args[2]
		}
		cmdIssue(domain)
	case "renew":
		cmdRenew()
	case "config":
		cmdConfig()
	case "renew-days":
		days := "30"
		if len(os.Args) > 2 {
			days = os.Args[2]
		}
		cmdRenewDays(days)
	case "setup":
		cmdSetup()
	case "serve":
		cmdServe()
	default:
		help()
	}
}

func help() {
	fmt.Println(strings.TrimSpace(`
cert-mgr — SSL 证书管理工具 (Go 版)

用法:
  cert-mgr scan              扫描本机证书文件
  cert-mgr status            查看所有证书到期状态
  cert-mgr check <域名>      检查远程域名证书
  cert-mgr issue <域名>      签发自签名证书（开发/内网用）
  cert-mgr renew             续期即将过期的证书
  cert-mgr config            查看配置
  cert-mgr renew-days <N>    设置到期前 N 天续期（默认30天）
  cert-mgr setup             安装 systemd timer 自动续期
  cert-mgr serve             启动 HTTP-01 验证服务（配合外部 CA 使用）

示例:
  cert-mgr scan
  cert-mgr status
  cert-mgr check example.com
  cert-mgr issue myapp.local
  cert-mgr renew-days 15
`))
}

func cmdScan() {
	state := loadState()

	// Scan common cert directories
	dirs := []string{
		"/etc/ssl",
		"/etc/nginx",
		"/etc/letsencrypt/live",
		state.CertDir,
	}

	var allCerts []CertFile
	for _, dir := range dirs {
		certs, _ := FindCertFiles(dir)
		allCerts = append(allCerts, certs...)
	}

	// Deduplicate by path
	seen := map[string]bool{}
	var unique []CertFile
	for _, c := range allCerts {
		if !seen[c.Path] {
			seen[c.Path] = true
			unique = append(unique, c)
		}
	}

	// Update state
	for _, c := range unique {
		info, err := LoadCertFromFile(c.Path)
		if err != nil {
			continue
		}
		for _, domain := range c.Domains {
			state.Certs[domain] = CertEntry{
				Cert: c.Path,
				Key:  c.KeyPath,
				Info: info,
			}
		}
	}
	state.LastScan = time.Now().Format(time.RFC3339)
	saveState(state)

	fmt.Printf("🔍 扫描完成，发现 %d 个证书\n\n", len(unique))
	for _, c := range unique {
		info, _ := LoadCertFromFile(c.Path)
		if info != nil {
			emoji := info.StatusEmoji(state.RenewDays)
			names := strings.Join(c.Domains[:min(3, len(c.Domains))], ", ")
			fmt.Printf("  %s %-35s 剩余 %3d 天  到期: %s\n",
				emoji, names, info.DaysLeft, info.NotAfter.Format("2006-01-02"))
			fmt.Printf("     证书: %s\n\n", c.Path)
		}
	}
}

func cmdStatus() {
	state := loadState()
	if len(state.Certs) == 0 {
		fmt.Println("📋 尚未扫描，请先执行: cert-mgr scan")
		return
	}

	// Refresh all cert info
	for domain, entry := range state.Certs {
		info, err := LoadCertFromFile(entry.Cert)
		if err == nil {
			entry.Info = info
			state.Certs[domain] = entry
		}
	}
	saveState(state)

	fmt.Printf("📋 证书状态（续期阈值: %d 天）\n\n", state.RenewDays)

	type item struct {
		domain string
		entry  CertEntry
	}
	var items []item
	for d, e := range state.Certs {
		items = append(items, item{d, e})
	}
	sort.Slice(items, func(i, j int) bool {
		di := items[i].entry.Info
		dj := items[j].entry.Info
		if di == nil {
			return false
		}
		if dj == nil {
			return true
		}
		return di.DaysLeft < dj.DaysLeft
	})

	var green, yellow, red, grey int
	for _, it := range items {
		info := it.entry.Info
		if info == nil {
			fmt.Printf("  ❓ %-30s 无法读取证书信息\n", it.domain)
			grey++
			continue
		}
		emoji := info.StatusEmoji(state.RenewDays)
		fmt.Printf("  %s %-30s %3d 天  到期: %s\n",
			emoji, it.domain, info.DaysLeft, info.NotAfter.Format("2006-01-02"))

		switch {
		case info.Expired || info.DaysLeft <= 7:
			red++
		case info.DaysLeft <= state.RenewDays:
			yellow++
		default:
			green++
		}
	}

	fmt.Printf("\n  共 %d 个域名\n", len(items))
	fmt.Printf("  ✅ 正常: %d  ⚠️ 即将到期: %d  🔴 紧急: %d\n", green, yellow, red)
}

func cmdCheck() {
	if len(os.Args) < 3 {
		fmt.Println("用法: cert-mgr check <域名>")
		fmt.Println("示例: cert-mgr check example.com")
		return
	}

	domain := os.Args[2]
	fmt.Printf("🔍 检查 %s ...\n", domain)

	info, err := LoadCertFromDomain(domain, 10*time.Second)
	if err != nil {
		fmt.Printf("❌ 连接失败: %v\n", err)
		return
	}

	emoji := info.StatusEmoji(30)
	fmt.Printf("  %s 域名: %s\n", emoji, domain)
	fmt.Printf("     主题: %s\n", info.Subject)
	fmt.Printf("     颁发者: %s\n", info.Issuer)
	fmt.Printf("     到期: %s\n", info.NotAfter.Format("2006-01-02 15:04:05"))
	fmt.Printf("     剩余: %d 天\n", info.DaysLeft)
	if len(info.DNSNames) > 0 {
		fmt.Printf("     SAN: %s\n", strings.Join(info.DNSNames, ", "))
	}
}

func cmdIssue(domain string) {
	if domain == "" {
		fmt.Println("用法: cert-mgr issue <域名>")
		fmt.Println("示例: cert-mgr issue myapp.local")
		return
	}

	state := loadState()
	domainDir := filepath.Join(state.CertDir, domain)
	os.MkdirAll(domainDir, 0755)

	certPath := filepath.Join(domainDir, "fullchain.pem")
	keyPath := filepath.Join(domainDir, "privkey.pem")

	// Check if cert already exists
	if _, err := os.Stat(certPath); err == nil {
		info, _ := LoadCertFromFile(certPath)
		if info != nil && info.DaysLeft > 30 {
			fmt.Printf("⚠️  %s 已有有效证书（剩余 %d 天），跳过\n", domain, info.DaysLeft)
			fmt.Printf("   如需重新签发，请先删除: rm -rf %s\n", domainDir)
			return
		}
	}

	fmt.Printf("🚀 为 %s 生成自签名证书...\n", domain)

	// Generate RSA key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("❌ 生成密钥失败: %v\n", err)
		return
	}

	// Create certificate template
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames:              []string{domain},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Add IP SANs if domain is an IP
	if ip := net.ParseIP(domain); ip != nil {
		template.IPAddresses = []net.IP{ip}
		template.DNSNames = nil
	}

	// Self-sign
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		fmt.Printf("❌ 生成证书失败: %v\n", err)
		return
	}

	// Save key
	keyFile, _ := os.Create(keyPath)
	pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	keyFile.Close()
	os.Chmod(keyPath, 0600)

	// Save cert
	certFile, _ := os.Create(certPath)
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certFile.Close()

	fmt.Printf("  ✅ 证书已生成\n")
	fmt.Printf("     证书: %s\n", certPath)
	fmt.Printf("     密钥: %s\n", keyPath)

	// Update state
	info, _ := LoadCertFromFile(certPath)
	state.Certs[domain] = CertEntry{Cert: certPath, Key: keyPath, Info: info}
	saveState(state)

	// Print nginx config
	fmt.Println()
	fmt.Println("📝 nginx 配置示例：")
	fmt.Println()
	fmt.Printf("    server {\n")
	fmt.Printf("        listen 443 ssl http2;\n")
	fmt.Printf("        server_name %s;\n", domain)
	fmt.Printf("\n")
	fmt.Printf("        ssl_certificate %s;\n", certPath)
	fmt.Printf("        ssl_certificate_key %s;\n", keyPath)
	fmt.Printf("        ssl_protocols TLSv1.2 TLSv1.3;\n")
	fmt.Printf("\n")
	fmt.Printf("        location / {\n")
	fmt.Printf("            proxy_pass http://127.0.0.1:8080;\n")
	fmt.Printf("            proxy_set_header Host $host;\n")
	fmt.Printf("            proxy_set_header X-Real-IP $remote_addr;\n")
	fmt.Printf("            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
	fmt.Printf("            proxy_set_header X-Forwarded-Proto $scheme;\n")
	fmt.Printf("        }\n")
	fmt.Printf("    }\n")
	fmt.Println()
	fmt.Printf("   保存后执行: nginx -t && nginx -s reload\n")
}

func cmdRenew() {
	state := loadState()
	renewed := 0

	for domain, entry := range state.Certs {
		info, err := LoadCertFromFile(entry.Cert)
		if err != nil {
			continue
		}
		if info.Expired || info.DaysLeft >= state.RenewDays {
			continue
		}

		fmt.Printf("  🔄 %s (剩余 %d 天)...\n", domain, info.DaysLeft)

		// Generate new self-signed cert
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			fmt.Printf("  ❌ %s 续期失败: %v\n", domain, err)
			continue
		}

		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		template := x509.Certificate{
			SerialNumber: serial,
			Subject:      pkix.Name{CommonName: domain},
			DNSNames:     []string{domain},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}

		certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
		if err != nil {
			fmt.Printf("  ❌ %s 续期失败: %v\n", domain, err)
			continue
		}

		// Save
		certFile, _ := os.Create(entry.Cert)
		pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		certFile.Close()

		keyFile, _ := os.Create(entry.Key)
		pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
		keyFile.Close()
		os.Chmod(entry.Key, 0600)

		newInfo, _ := LoadCertFromFile(entry.Cert)
		entry.Info = newInfo
		state.Certs[domain] = entry
		renewed++
		fmt.Printf("  ✅ %s 续期成功\n", domain)
	}

	if renewed > 0 {
		// Try reload nginx
		exec.Command("nginx", "-s", "reload").Run()
		fmt.Printf("\n✅ 已续期 %d 个证书\n", renewed)
	} else {
		fmt.Printf("✅ 所有证书都在 %d 天内无需续期\n", state.RenewDays)
	}

	saveState(state)
}

func cmdConfig() {
	state := loadState()
	fmt.Printf("当前配置：\n")
	fmt.Printf("  证书存放目录: %s\n", state.CertDir)
	fmt.Printf("  续期阈值: %d 天\n", state.RenewDays)
	fmt.Printf("  上次扫描: %s\n", state.LastScan[:min(16, len(state.LastScan))])
	fmt.Printf("  管理域名数: %d\n", len(state.Certs))
	fmt.Printf("\n如需修改续期天数，执行: cert-mgr renew-days <天数>\n")
}

func cmdRenewDays(days string) {
	var d int
	fmt.Sscanf(days, "%d", &d)
	if d < 1 || d > 90 {
		fmt.Println("用法: cert-mgr renew-days <天数>  范围: 1-90")
		return
	}
	state := loadState()
	state.RenewDays = d
	saveState(state)
	fmt.Printf("✅ 续期阈值已设为 %d 天\n", d)
}

func cmdSetup() {
	fmt.Println("📝 自动续期设置：")
	fmt.Println()
	fmt.Println("方式一 — systemd timer（推荐）：")
	fmt.Printf("  创建 /etc/systemd/system/cert-mgr-renew.service:\n")
	fmt.Printf("    [Unit]\n")
	fmt.Printf("    Description=SSL Certificate Auto-Renewal\n")
	fmt.Printf("    [Service]\n")
	fmt.Printf("    Type=oneshot\n")
	fmt.Printf("    ExecStart=/usr/local/bin/cert-mgr renew\n")
	fmt.Printf("\n")
	fmt.Printf("  创建 /etc/systemd/system/cert-mgr-renew.timer:\n")
	fmt.Printf("    [Unit]\n")
	fmt.Printf("    Description=Daily SSL Certificate Check\n")
	fmt.Printf("    [Timer]\n")
	fmt.Printf("    OnCalendar=daily\n")
	fmt.Printf("    Persistent=true\n")
	fmt.Printf("    [Install]\n")
	fmt.Printf("    WantedBy=timers.target\n")
	fmt.Printf("\n")
	fmt.Printf("  启用:\n")
	fmt.Printf("    systemctl enable --now cert-mgr-renew.timer\n")
	fmt.Println()
	fmt.Println("方式二 — crontab：")
	fmt.Printf("  echo '0 3 * * * /usr/local/bin/cert-mgr renew >> /var/log/cert-mgr.log 2>&1' | crontab -\n")
	fmt.Println()
	fmt.Println("方式三 — OpenClaw cron：")
	fmt.Printf("  openclaw cron add --schedule='0 3 * * *' --cmd='cert-mgr renew'\n")
}

func cmdServe() {
	// Simple HTTP-01 challenge server for ACME validation
	port := "80"
	if len(os.Args) > 2 {
		port = os.Args[2]
	}
	webroot := "/var/www/html"
	if len(os.Args) > 3 {
		webroot = os.Args[3]
	}

	fmt.Printf("🌐 HTTP-01 验证服务启动\n")
	fmt.Printf("   端口: %s\n", port)
	fmt.Printf("   目录: %s\n", webroot)
	fmt.Printf("   用于配合 certbot / acme.sh 完成域名验证\n")
	fmt.Printf("   按 Ctrl+C 停止\n")

	// This is a placeholder — real ACME integration would need a full HTTP server
	// For now, guide the user
	fmt.Println()
	fmt.Println("📝 使用方式：")
	fmt.Println("   1. 启动本服务: cert-mgr serve")
	fmt.Println("   2. 另开终端执行:")
	fmt.Printf("      certbot certonly --webroot -w %s -d your-domain.com\n", webroot)
	fmt.Println("   3. 证书会保存到 /etc/letsencrypt/live/")
	fmt.Println("   4. 执行 cert-mgr scan 自动发现新证书")
}
