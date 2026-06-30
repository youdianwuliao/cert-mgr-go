# cert-mgr — SSL 证书管理工具 (Go 版)

纯 Go 实现，零外部依赖，单二进制文件。签发、扫描、检查、续期一条龙。

## 为什么重写

旧版 Python 依赖 acme.sh 第三方工具，安装链路长、环境耦合重。Go 版用标准库 `crypto/tls` + `crypto/x509` 搞定一切，编译出来就是一个几 MB 的二进制，拷到服务器上直接跑。

## 安装

```bash
# 编译
git clone https://github.com/youdianwuliao/cert-mgr-go.git
cd cert-mgr-go
go build -o cert-mgr .

# 安装到系统
sudo cp cert-mgr /usr/local/bin/
```

或者直接下载 [Releases](https://github.com/youdianwuliao/cert-mgr-go/releases) 里的预编译二进制。

## 使用

### 扫描证书（优先 nginx）

```bash
cert-mgr scan
```

解析 nginx 配置中的 SSL 站点，自动发现证书和密钥路径。未安装 nginx 时回退到目录扫描。

### 查看证书状态

```bash
cert-mgr status
```

```
📋 证书状态（续期阈值: 30 天）

  [nginx 证书]
  ✅ example.com                    81 天  到期: 2026-09-18
  ⚠️ api.example.com                25 天  到期: 2026-07-24

  [其他证书]
  ✅ myapp.local                   365 天  到期: 2027-06-30

  共 3 个域名  ✅ 正常: 2  ⚠️ 即将到期: 1  🔴 紧急: 0
```

nginx 证书在前，一目了然。

### 检查远程域名

```bash
cert-mgr check baidu.com
```

```
🔍 检查 baidu.com ...
  ✅ 域名: baidu.com
     颁发者: GlobalSign RSA OV SSL CA 2018
     到期: 2026-08-10 07:01:01
     剩余: 42 天
```

### 签发证书

```bash
# 默认目录 /etc/ssl/cert-mgr
cert-mgr issue myapp.local

# 指定输出目录（无 nginx 环境）
cert-mgr issue myapp.local --dir /opt/certs

# 强制覆盖已有证书
cert-mgr issue myapp.local --force
```

生成自签名证书（开发/内网用），自动打印 nginx 配置示例。

### 续期证书

```bash
# 一键续期所有即将过期证书
cert-mgr renew

# 续期指定域名
cert-mgr renew example.com

# 强制续期（忽略天数检查）
cert-mgr renew example.com --force
```

续期直接覆盖旧证书文件，自动执行 `nginx -t && nginx -s reload`。

### 配置续期阈值

```bash
cert-mgr renew-days 15   # 到期前 15 天触发续期（默认 30 天）
cert-mgr config          # 查看当前配置
```

### 自动续期部署

```bash
cert-mgr setup   # 查看 systemd timer / crontab 配置方法
```

## 命令一览

| 命令 | 说明 |
|------|------|
| `cert-mgr scan` | 扫描 nginx 证书（优先）+ 目录证书 |
| `cert-mgr status` | 查看所有证书到期状态（nginx 在前） |
| `cert-mgr check <域名>` | 检查远程域名证书 |
| `cert-mgr issue <域名>` | 签发证书，支持 --dir / --force |
| `cert-mgr renew [域名]` | 续期指定域名或一键续期全部 |
| `cert-mgr config` | 查看当前配置 |
| `cert-mgr renew-days <N>` | 设置续期阈值（默认 30 天） |
| `cert-mgr setup` | 显示自动续期部署方式 |
| `cert-mgr serve` | HTTP-01 验证服务（配合 certbot） |

## 自动续期部署

### systemd timer（推荐）

```ini
# /etc/systemd/system/cert-mgr-renew.service
[Unit]
Description=SSL Certificate Auto-Renewal
[Service]
Type=oneshot
ExecStart=/usr/local/bin/cert-mgr renew

# /etc/systemd/system/cert-mgr-renew.timer
[Unit]
Description=Daily SSL Certificate Check
[Timer]
OnCalendar=daily
Persistent=true
[Install]
WantedBy=timers.target
```

```bash
systemctl enable --now cert-mgr-renew.timer
```

### crontab

```bash
echo '0 3 * * * /usr/local/bin/cert-mgr renew >> /var/log/cert-mgr.log 2>&1' | crontab -
```

## 与 Python 版对比

| | Python 版 | Go 版 |
|---|---|---|
| 依赖 | Python3 + acme.sh + openssl | 无（标准库） |
| 安装 | clone + pip + acme.sh install | 单二进制拷贝 |
| 体积 | ~50KB + Python 运行时 | ~4MB 单文件 |
| 跨平台 | 需 Python 环境 | 交叉编译即用 |
| 远程检查 | ❌ | ✅ `cert-mgr check` |
| nginx 集成 | ❌ | ✅ 解析 nginx 配置 |
| Let's Encrypt | ✅ 通过 acme.sh | 配合 certbot 使用 |

## 许可

MIT
