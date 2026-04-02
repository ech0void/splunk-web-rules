# Splunk Sourcetype Setup — Nginx & Apache (Ubuntu)

Bu sənəd Ubuntu serverinizdə Nginx və Apache log-larını Splunk-a düzgün göndərməyi izah edir.

---

## 1. Splunk Universal Forwarder Qurulumu (Ubuntu)

```bash
# Download Splunk UF
wget -O splunkforwarder.deb "https://download.splunk.com/products/universalforwarder/releases/9.2.0/linux/splunkforwarder-9.2.0-amd64.deb"

# Install
sudo dpkg -i splunkforwarder.deb

# Start and enable on boot
sudo /opt/splunkforwarder/bin/splunk start --accept-license
sudo /opt/splunkforwarder/bin/splunk enable boot-start

# Forward to your Splunk Enterprise server
sudo /opt/splunkforwarder/bin/splunk add forward-server YOUR_SPLUNK_HOST:9997
```

---

## 2. inputs.conf — Log Monitoring

Faylı yarat: `/opt/splunkforwarder/etc/system/local/inputs.conf`

```ini
# ── Nginx ──────────────────────────────────────────────────
[monitor:///var/log/nginx/access.log]
sourcetype = nginx_access
index      = web
disabled   = false

[monitor:///var/log/nginx/access.log.*]
sourcetype = nginx_access
index      = web

[monitor:///var/log/nginx/error.log]
sourcetype = nginx_error
index      = web

# ── Apache ─────────────────────────────────────────────────
[monitor:///var/log/apache2/access.log]
sourcetype = apache_access
index      = web
disabled   = false

[monitor:///var/log/apache2/error.log]
sourcetype = apache_error
index      = web

# Virtual host logs (if any)
[monitor:///var/log/apache2/*_access.log]
sourcetype = apache_access
index      = web
```

---

## 3. props.conf — Field Extraction

Faylı yarat: `/opt/splunkforwarder/etc/system/local/props.conf`

```ini
# ── Nginx Access Log ───────────────────────────────────────
[nginx_access]
SHOULD_LINEMERGE = false
LINE_BREAKER      = ([\r\n]+)
NO_BINARY_CHECK   = true
CHARSET           = UTF-8
# Standard Nginx combined log format:
# 1.2.3.4 - user [01/Jan/2025:12:00:00 +0000] "GET /path HTTP/1.1" 200 512 "referer" "UA"
TRANSFORMS-nginx_access = nginx_access_kv
EXTRACT-nginx_fields = ^(?P<src_ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<uri>[^\s"]+)\s+(?P<http_version>[^"]+)"\s+(?P<status>\d+)\s+(?P<bytes>\d+|-)\s+"(?P<referer>[^"]+)"\s+"(?P<useragent>[^"]+)"

# ── Apache Access Log ──────────────────────────────────────
[apache_access]
SHOULD_LINEMERGE = false
LINE_BREAKER      = ([\r\n]+)
NO_BINARY_CHECK   = true
CHARSET           = UTF-8
EXTRACT-apache_fields = ^(?P<src_ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<uri>[^\s"]+)\s+(?P<http_version>[^"]+)"\s+(?P<status>\d+)\s+(?P<bytes>\d+|-)\s+"(?P<referer>[^"]+)"\s+"(?P<useragent>[^"]+)"
```

---

## 4. Index Yaratma (Splunk Enterprise-də)

Splunk Web UI → **Settings → Indexes → New Index**

| Field | Value |
|-------|-------|
| Index Name | `web` |
| Max Size | `10 GB` (öz ehtiyacına görə) |
| Retention | `90 days` |

Və ya CLI ilə:
```bash
/opt/splunk/bin/splunk add index web
```

---

## 5. Splunk API Token Yaratma

1. Splunk Web → sağ üst köşə → **Settings → Tokens**
2. **New Token** → Description: `siem-deploy-api`
3. Token-i kopyala → `.env` faylına yapışdır

---

## 6. Yoxlama

```bash
# Logs gəlirmi?
/opt/splunkforwarder/bin/splunk search "index=web | head 5" -auth admin:password

# Forwarder statusu
/opt/splunkforwarder/bin/splunk list forward-server
```

Splunk-da bu SPL ilə yoxla:
```spl
index=web sourcetype=nginx_access | head 20 | table _time, src_ip, method, uri, status
```
