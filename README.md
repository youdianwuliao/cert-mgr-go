# cert-mgr — SSL 证书管理工具 (Go 版)

纯 Go 实现，零外部依赖，单二进制文件。签发、扫描、检查、续期一条龙。

## 为什么重写

旧版 Python 依赖 acme.sh 第三方工具，安装链路长、环境耦合重。Go 版用标准库 `crypto/tls` + `crypto/x509` 搞定一切，编译出来就是一个几 MB 的二进制，拷到服务器上直接跑。

## 安装

```bash
# 编译
git clone https://github.com/youdianwuliao/cert-mgr.git
cd cert-mgr
go build -o cert-mgr .

# 安装到系统
sudo cp cert-mgr /usr/local/bin/
```

或者直接下载 [Releases](https://github.com/youdianwuliao/cert-mgr/releases) 里的预编译二进制。

## 使用

### 扫描本机证书

```bash
cert-mgr scan
```

自动扫描 `/etc/ssl`、`/etc/nginx`、`/etc/letsencrypt/live` 等目录，发现所有证书并记录状态。

### 查看证书状态

```bash
cert-mgr status
```

```
📋 证书状态（续期阈值: 30 天）

  ✅ example.com                    81 天  到期: 2026-09-18
  ⚠️ api.example.com                25 天  到期: 2026-07-24
  🔴 old.example.com                 5 天  到期: 2026-07-04

  共 3 个域名
  ✅ 正常: 1  ⚠️ 即将到期: 1  🔴 紧急: 1
```

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
cert-mgr issue myapp.local
```

生成自签名证书（开发/内网用），自动打印 nginx 配置示例。

### 自动续期

```bash
cert-mgr renew          # 手动续期即将过期的证书
cert-mgr renew-days 15  # 设置到期前 15 天触发续期
cert-mgr setup          # 查看 systemd timer / crontab 配置方法
```

### 查看配置

```bash
cert-mgr config
```

## 命令一览

| 命令 | 说明 |
|------|------|
| `cert-mgr scan` | 扫描本机证书文件 |
| `cert-mgr status` | 查看所有证书到期状态 |
| `cert-mgr check <域名>` | 检查远程域名证书 |
| `cert-mgr issue <域名>` | 签发自签名证书 + 打印 nginx 配置 |
| `cert-mgr renew` | 续期即将过期的证书 |
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
| 体积 | ~50KB + Python 运行时 | ~8MB 单文件 |
| 跨平台 | 需 Python 环境 | 交叉编译即用 |
| 远程检查 | ❌ | ✅ `cert-mgr check` |
| Let's Encrypt | ✅ 通过 acme.sh | 配合 certbot 使用 |

## 许可

MIT
