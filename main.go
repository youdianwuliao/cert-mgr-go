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
	Cert   string    `json:"cert"`
	Key    string    `json:"key"`
	Source string    `json:"source"` // "nginx" or "manual"
	Info   *CertInfo `json:"info"`
}

var (
	confDir   = "/etc/ssl/cert-mgr"
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
		cmdIssue()
	case "renew":
		cmdRenew()
	case "config":
		cmdConfig()
	case "renew-days":
		cmdRenewDays()
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
  cert-mgr scan              扫描 nginx 证书（优先）和本机证书
  cert-mgr status            查看所有证书到期状态（nginx 在前）
  cert-mgr check <域名>       检查远程域名证书
  cert-mgr issue <域名>       签发自签名证书，支持 --dir 指定目录
  cert-mgr renew [域名]       续期证书：指定域名或一键续期全部
  cert-mgr config            查看配置
  cert-mgr renew-days <N>     设置到期前 N 天续期（默认30天）
  cert-mgr setup             安装 systemd timer 自动续期
  cert-mgr serve             启动 HTTP-01 验证服务（配合外部 CA 使用）

选项:
  --dir <path>   指定证书输出目录（issue 命令）
  --force        强制覆盖已有证书（issue/renew 命令）

示例:
  cert-mgr scan
  cert-mgr status
  cert-mgr check example.com
  cert-mgr issue myapp.local
  cert-mgr issue myapp.local --dir /opt/certs
  cert-mgr renew                # 一键续期全部即将过期证书
  cert-mgr renew example.com    # 续期指定域名
  cert-mgr renew-days 15
`))
}

func parseArgs() (map[string]string, []string) {
	flags := map[string]string{}
	var positional []string
	for i := 2; i < len(os.Args); i++ {
		arg := os.Args[i]
		if strings.HasPrefix(arg, "--") {
			key := strings.TrimPrefix(arg, "--")
			if i+1 < len(os.Args) && !strings.HasPrefix(os.Args[i+1], "--") {
				flags[key] = os.Args[i+1]
				i++
			} else {
				flags[key] = "true"
			}
		} else {
			positional = append(positional, arg)
		}
	}
	return flags, positional
}

func cmdScan() {
	state := loadState()
	found := 0

	// Priority 1: nginx config
	if IsNginxInstalled() {
		fmt.Println("🔍 解析 nginx 配置...")
		nginxCerts, err := FindNginxCerts()
		if err == nil && len(nginxCerts) > 0 {
			fmt.Printf("  发现 %d 个 nginx SSL 站点\n\n", len(nginxCerts))
			for _, nc := range nginxCerts {
				info, err := LoadCertFromFile(nc.CertPath)
				if err != nil {
					fmt.Printf("  ❓ %-35s 证书文件不可读: %s\n", nc.ServerName, nc.CertPath)
					continue
				}
				emoji := info.StatusEmoji(state.RenewDays)
				fmt.Printf("  %s %-35s 剩余 %3d 天  到期: %s\n",
					emoji, nc.ServerName, info.DaysLeft, info.NotAfter.Format("2006-01-02"))
				fmt.Printf("     证书: %s\n", nc.CertPath)
				fmt.Printf("     密钥: %s\n\n", nc.KeyPath)

				// Register in state
				for _, domain := range nc.Domains {
					state.Certs[domain] = CertEntry{
						Cert:   nc.CertPath,
						Key:    nc.KeyPath,
						Source: "nginx",
						Info:   info,
					}
				}
				found++
			}
			state.LastScan = time.Now().Format(time.RFC3339)
			saveState(state)
			fmt.Printf("✅ 已记录 %d 个 nginx 证书\n", found)
			return
		}
		fmt.Println("  nginx 未找到 SSL 配置\n")
	}

	// Fallback: scan cert directories
	fmt.Println("🔍 扫描证书目录...")
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

	seen := map[string]bool{}
	var unique []CertFile
	for _, c := range allCerts {
		if !seen[c.Path] {
			seen[c.Path] = true
			unique = append(unique, c)
		}
	}

	for _, c := range unique {
		info, err := LoadCertFromFile(c.Path)
		if err != nil {
			continue
		}
		for _, domain := range c.Domains {
			state.Certs[domain] = CertEntry{
				Cert:   c.Path,
				Key:    c.KeyPath,
				Source: "manual",
				Info:   info,
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

	// Refresh all cert info
	for domain, entry := range state.Certs {
		info, err := LoadCertFromFile(entry.Cert)
		if err == nil {
			entry.Info = info
			state.Certs[domain] = entry
		}
	}
	saveState(state)

	if len(state.Certs) == 0 {
		fmt.Println("📋 尚未扫描，请先执行: cert-mgr scan")
		return
	}

	fmt.Printf("📋 证书状态（续期阈值: %d 天）\n\n", state.RenewDays)

	type item struct {
		domain string
		entry  CertEntry
	}
	var nginxCerts, manualCerts []item
	for d, e := range state.Certs {
		if e.Source == "nginx" {
			nginxCerts = append(nginxCerts, item{d, e})
		} else {
			manualCerts = append(manualCerts, item{d, e})
		}
	}

	sortItems := func(items []item) {
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
	}
	sortItems(nginxCerts)
	sortItems(manualCerts)

	printGroup := func(label string, items []item) {
		if len(items) == 0 {
			return
		}
		fmt.Printf("  [%s]\n", label)
		for _, it := range items {
			info := it.entry.Info
			if info == nil {
				fmt.Printf("  ❓ %-35s 无法读取证书\n", it.domain)
				continue
			}
			emoji := info.StatusEmoji(state.RenewDays)
			fmt.Printf("  %s %-35s %3d 天  到期: %s\n",
				emoji, it.domain, info.DaysLeft, info.NotAfter.Format("2006-01-02"))
		}
		fmt.Println()
	}

	printGroup("nginx 证书", nginxCerts)
	printGroup("其他证书", manualCerts)

	total := len(nginxCerts) + len(manualCerts)
	var green, yellow, red int
	for _, items := range [][]item{nginxCerts, manualCerts} {
		for _, it := range items {
			info := it.entry.Info
			if info == nil {
				continue
			}
			switch {
			case info.Expired || info.DaysLeft <= 7:
				red++
			case info.DaysLeft <= state.RenewDays:
				yellow++
			default:
				green++
			}
		}
	}

	fmt.Printf("  共 %d 个域名  ✅ 正常: %d  ⚠️ 即将到期: %d  🔴 紧急: %d\n", total, green, yellow, red)
}

func cmdCheck() {
	_, positional := parseArgs()
	if len(positional) < 1 {
		fmt.Println("用法: cert-mgr check <域名>")
		fmt.Println("示例: cert-mgr check example.com")
		return
	}

	domain := positional[0]
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

func cmdIssue() {
	flags, positional := parseArgs()
	if len(positional) < 1 {
		fmt.Println("用法: cert-mgr issue <域名> [--dir <目录>] [--force]")
		fmt.Println("示例: cert-mgr issue myapp.local")
		fmt.Println("      cert-mgr issue myapp.local --dir /opt/certs")
		return
	}

	domain := positional[0]
	state := loadState()

	// Determine output directory
	outputDir := state.CertDir
	if dir, ok := flags["dir"]; ok {
		outputDir = dir
	}
	domainDir := filepath.Join(outputDir, domain)
	os.MkdirAll(domainDir, 0755)

	certPath := filepath.Join(domainDir, "fullchain.pem")
	keyPath := filepath.Join(domainDir, "privkey.pem")

	// Check existing (skip if not forced)
	_, force := flags["force"]
	if !force {
		if _, err := os.Stat(certPath); err == nil {
			info, _ := LoadCertFromFile(certPath)
			if info != nil && info.DaysLeft > 30 {
				fmt.Printf("⚠️  %s 已有有效证书（剩余 %d 天），跳过\n", domain, info.DaysLeft)
				fmt.Printf("   如需重新签发，加 --force\n")
				return
			}
		}
	}

	fmt.Printf("🚀 为 %s 生成自签名证书...\n", domain)
	if outputDir != state.CertDir {
		fmt.Printf("   输出目录: %s\n", outputDir)
	}

	// Generate RSA key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("❌ 生成密钥失败: %v\n", err)
		return
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames:              []string{domain},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(domain); ip != nil {
		template.IPAddresses = []net.IP{ip}
		template.DNSNames = nil
	}

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
	state.Certs[domain] = CertEntry{Cert: certPath, Key: keyPath, Source: "manual", Info: info}
	saveState(state)

	// Print nginx config snippet
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
	flags, positional := parseArgs()
	state := loadState()

	// Specific domain renewal
	if len(positional) > 0 {
		domain := positional[0]
		_, force := flags["force"]
		renewDomain(state, domain, force)
		return
	}

	// Renew all near-expiry certificates (deduplicate by cert file path)
	renewed := 0
	renewedFiles := map[string]bool{}
	domains := sortedDomainKeys(state)

	for _, domain := range domains {
		entry := state.Certs[domain]
		if renewedFiles[entry.Cert] {
			continue // same cert file already renewed
		}

		info, err := LoadCertFromFile(entry.Cert)
		if err != nil {
			continue
		}

		// Skip if not near expiry
		if !info.Expired && info.DaysLeft > state.RenewDays {
			continue
		}

		renewCertFile(state, domain, entry, info)
		renewedFiles[entry.Cert] = true
		renewed++
	}

	if renewed > 0 {
		// Reload nginx if available
		if IsNginxInstalled() {
			fmt.Println()
			if err := ReloadNginx(); err != nil {
				fmt.Printf("⚠️  nginx 重载失败: %v\n", err)
			} else {
				fmt.Println("✅ nginx 已重载")
			}
		}
		fmt.Printf("\n✅ 已续期 %d 个证书\n", renewed)
	} else {
		fmt.Printf("✅ 所有证书都在 %d 天内无需续期\n", state.RenewDays)
	}

	saveState(state)
}

func renewDomain(state State, domain string, force bool) {
	entry, exists := state.Certs[domain]
	if !exists {
		// Search all known certs for one whose SANs include this domain
		for d, e := range state.Certs {
			// Load cert info if not cached
			if e.Info == nil {
				info, err := LoadCertFromFile(e.Cert)
				if err == nil {
					e.Info = info
					state.Certs[d] = e
				}
			}
			if e.Info != nil {
				for _, san := range e.Info.DNSNames {
					if san == domain {
						entry = e
						exists = true
						break
					}
				}
			}
			if exists {
				break
			}
		}
	}
	if !exists {
		// Try to find in nginx config
		if IsNginxInstalled() {
			nginxCerts, err := FindNginxCerts()
			if err == nil {
				for _, nc := range nginxCerts {
					for _, d := range nc.Domains {
						if d == domain {
							entry = CertEntry{
								Cert:   nc.CertPath,
								Key:    nc.KeyPath,
								Source: "nginx",
							}
							exists = true
							break
						}
					}
					if exists {
						break
					}
				}
			}
		}
		if !exists {
			fmt.Printf("❌ 未找到域名 %s 的证书\n", domain)
			fmt.Printf("   请先执行 cert-mgr scan\n")
			return
		}
	}

	info, err := LoadCertFromFile(entry.Cert)
	if err != nil {
		fmt.Printf("❌ 读取证书失败: %v\n", err)
		return
	}

	if !force && !info.Expired && info.DaysLeft > state.RenewDays {
		fmt.Printf("✅ %s 证书有效（剩余 %d 天），无需续期\n", domain, info.DaysLeft)
		fmt.Printf("   加 --force 强制续期\n")
		return
	}

	renewCertFile(state, domain, entry, info)
	saveState(state)

	// Reload nginx
	if IsNginxInstalled() {
		if err := ReloadNginx(); err != nil {
			fmt.Printf("⚠️  nginx 重载失败: %v\n", err)
		} else {
			fmt.Println("✅ nginx 已重载")
		}
	}
}

func renewCertFile(state State, domain string, entry CertEntry, oldInfo *CertInfo) {
	// Preserve all SANs from the original certificate
	dnsNames := make([]string, len(oldInfo.DNSNames))
	copy(dnsNames, oldInfo.DNSNames)
	if len(dnsNames) == 0 {
		dnsNames = []string{domain}
	}

	// Display (don't mutate dnsNames)
	if len(dnsNames) > 3 {
		fmt.Printf("🔄 %s (剩余 %d 天) SAN: %s... (%d个)\n", domain, oldInfo.DaysLeft,
			strings.Join(dnsNames[:3], ", "), len(dnsNames))
	} else {
		fmt.Printf("🔄 %s (剩余 %d 天) SAN: %s\n", domain, oldInfo.DaysLeft, strings.Join(dnsNames, ", "))
	}

	// Generate new key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("❌ %s 续期失败: %v\n", domain, err)
		return
	}

	commonName := domain
	if oldInfo.Subject != "" {
		commonName = oldInfo.Subject
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     dnsNames,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		fmt.Printf("❌ %s 续期失败: %v\n", err)
		return
	}

	// Overwrite old certificate
	certFile, err := os.Create(entry.Cert)
	if err != nil {
		fmt.Printf("❌ %s 写入证书失败: %v\n", domain, err)
		return
	}
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certFile.Close()

	// Overwrite old key
	if entry.Key != "" {
		keyFile, err := os.Create(entry.Key)
		if err != nil {
			fmt.Printf("⚠️  %s 写入密钥失败: %v\n", domain, err)
		} else {
			pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
			keyFile.Close()
			os.Chmod(entry.Key, 0600)
		}
	}

	newInfo, _ := LoadCertFromFile(entry.Cert)
	entry.Info = newInfo

	// Update all domains sharing this certificate
	for _, d := range dnsNames {
		state.Certs[d] = entry
	}
	state.Certs[domain] = entry
	fmt.Printf("✅ %s 续期成功（%d 个域名）\n", domain, len(dnsNames))
}

func sortedDomainKeys(state State) []string {
	keys := make([]string, 0, len(state.Certs))
	for k := range state.Certs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func cmdConfig() {
	state := loadState()
	fmt.Printf("当前配置：\n")
	fmt.Printf("  证书存放目录: %s\n", state.CertDir)
	fmt.Printf("  续期阈值: %d 天\n", state.RenewDays)
	if state.LastScan != "" {
		fmt.Printf("  上次扫描: %s\n", state.LastScan[:min(16, len(state.LastScan))])
	}
	fmt.Printf("  管理域名数: %d\n", len(state.Certs))
	if IsNginxInstalled() {
		fmt.Printf("  nginx: 已安装\n")
	} else {
		fmt.Printf("  nginx: 未安装\n")
	}
	fmt.Printf("\n如需修改续期天数: cert-mgr renew-days <天数>\n")
}

func cmdRenewDays() {
	_, positional := parseArgs()
	if len(positional) < 1 {
		fmt.Println("用法: cert-mgr renew-days <天数>")
		fmt.Println("示例: cert-mgr renew-days 15")
		return
	}

	var d int
	fmt.Sscanf(positional[0], "%d", &d)
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
	_, positional := parseArgs()
	port := "80"
	if len(positional) > 0 {
		port = positional[0]
	}
	webroot := "/var/www/html"
	if len(positional) > 1 {
		webroot = positional[1]
	}

	fmt.Printf("🌐 HTTP-01 验证服务启动\n")
	fmt.Printf("   端口: %s\n", port)
	fmt.Printf("   目录: %s\n", webroot)
	fmt.Printf("   用于配合 certbot / acme.sh 完成域名验证\n")
	fmt.Printf("   按 Ctrl+C 停止\n")

	fmt.Println()
	fmt.Println("📝 使用方式：")
	fmt.Println("   1. 启动本服务: cert-mgr serve")
	fmt.Println("   2. 另开终端执行:")
	fmt.Printf("      certbot certonly --webroot -w %s -d your-domain.com\n", webroot)
	fmt.Println("   3. 证书会保存到 /etc/letsencrypt/live/")
	fmt.Println("   4. 执行 cert-mgr scan 自动发现新证书")
}

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// execCommand is a wrapper for testing (used in nginx.go via os/exec directly)
func execCommand(name string, args ...string) *exec.Cmd {
	return exec.Command(name, args...)
}
