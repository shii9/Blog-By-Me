# curl: The Complete Reference (Beginner to Advanced)

> **A complete reference — beginner fundamentals through bug-bounty tradecraft.**
>
> *Compiled from curl's official tutorial ([curl.se/docs/tutorial.html](https://curl.se/docs/tutorial.html)) and current bug-bounty field practice (July 2026).*

---

## Table of Contents
1. [Fundamentals](#1-fundamentals)
2. [Install & Verify](#2-install--verify)
3. [Anatomy of a Request](#3-anatomy-of-a-request)
4. [Master Flag Reference](#4-master-flag-reference)
5. [HTTP Methods in Depth](#5-http-methods-in-depth)
6. [Sending Data](#6-sending-data)
7. [Headers](#7-headers)
8. [Authentication](#8-authentication)
9. [Cookies & Sessions](#9-cookies--sessions)
10. [Redirects](#10-redirects)
11. [TLS / SSL](#11-tls--ssl)
12. [Proxying (Burp / ZAP Integration)](#12-proxying-burp--zap-integration)
13. [Output Control & Timing](#13-output-control--timing)
14. [Verbose & Debug](#14-verbose--debug)
15. [Automation & Scripting](#15-automation--scripting)
16. [Security Research Arsenal](#16-security-research-arsenal)
17. [One-Screen Cheat Sheet](#17-one-screen-cheat-sheet)

---

## 1. Fundamentals

`curl` (Client URL) is a powerful command-line tool and library (`libcurl`) designed for transferring data using various network protocols. First released by **Daniel Stenberg** in 1997, it supports HTTP, HTTPS, FTP, SFTP, SCP, SMB, LDAP, TELNET, DICT, and many others in a single, stateless binary. It is pre-installed on almost every modern operating system and powers countless scripts, applications, and IoT devices.

### Why use curl over a GUI client for security work?
Tools like Burp Suite, Postman, or web browsers automatically modify requests before sending them. They:
* Normalize HTTP headers
* Deduplicate parameters
* "Fix" malformed syntax

`curl` sends the **exact bytes** you define. This behavior is crucial when testing for header injection, verb tampering, or malformed inputs that GUIs silently correct.

### How curl actually behaves
* **Execution Flow:** DNS Resolution → TCP Connection → TLS Handshake (if HTTPS) → Request sent → Response body printed to `stdout` by default.
* **Limitations:** It does not run client-side JavaScript, render HTML, or follow HTTP redirects automatically (unless `-L` is supplied).
* **Exit Codes:** An exit code of `0` means the network transfer succeeded, **not** that the HTTP status was successful. A `404` or `500` response will still return exit code `0` unless you pass the `-f` flag.
* **Under the Hood:** `libcurl` powers `curl` itself, PHP's cURL extension, Python's `pycurl`, and embedded systems. Understanding `curl` flags directly aids in reading and writing code that utilizes these libraries.

---

## 2. Install & Verify

Most modern systems have `curl` pre-installed. However, for security auditing, it is important to know which TLS backends and protocols your build supports.

### Linux
```bash
# Debian / Ubuntu / Kali Linux
sudo apt update && sudo apt install curl -y
```

### Windows
```powershell
# Bundled with Windows 10 (build 1803+). To upgrade/install latest via winget:
winget install cURL.cURL
```

### Verify Build & Protocol Support
To check compiled-in features, run:
```bash
curl --version
```
This command displays:
* The active version of `curl` and `libcurl`
* The SSL/TLS backend in use (OpenSSL, LibreSSL, GnuTLS, Schannel)
* Supported protocols (HTTP/2, HTTP/3, IDN, PSL, etc.)

> [!WARNING]
> Testing a target using an outdated `curl` version without HTTP/3 or TLS 1.3 support might yield different results compared to modern web browsers.

---

## 3. Anatomy of a Request

Every `curl` command follows a simple syntax:
```bash
curl [options] [URL]
```

### Key Formatting Rules
* **Short Flags:** Can be combined. For example, `-sS` is equivalent to `-s -S`, and `-iL` is equivalent to `-i -L`.
* **Long Flags:** Every long flag has a short counterpart where applicable (e.g., `--request` is equivalent to `-X`).
* **Repeating Flags:** Some flags can stack (e.g., `-H` for headers and `-F` for form data). If you repeat a flag that takes a single value (such as `-X` or `-d`), only the last instance on the command line is evaluated.
* **URL Quoting:** Always wrap your URLs in quotes. Characters like `&`, `?`, `#`, and spaces have special meanings in terminal shells and can break execution if unquoted.
* **Multiple Targets:** Specifying multiple URLs on a single command line executes sequential transfers, reusing the TCP connection when hosts match.

---

## 4. Master Flag Reference

Here is a comprehensive reference of essential `curl` flags, grouped by function.

### Request Configuration
| Short Flag | Long Flag | Description | Example |
| :--- | :--- | :--- | :--- |
| `-X` | `--request <method>` | Set the HTTP method (GET is default) | `curl -X POST https://target.com` |
| `-G` | `--get` | Convert data specified with `-d` into a query string | `curl -G -d "q=test" https://target.com/search` |
| | `--next` | Start a new request configuration sequence | `curl https://a.com --next -X POST https://b.com` |
| | `--http1.1` | Force HTTP/1.1 protocol | `curl --http1.1 https://target.com` |
| | `--http2` | Force HTTP/2 protocol (requires TLS ALPN) | `curl --http2 https://target.com` |
| | `--http2-prior-knowledge` | Force HTTP/2 without protocol negotiation | `curl --http2-prior-knowledge http://target.com` |
| | `--http3` | Force HTTP/3 (QUIC) | `curl --http3 https://target.com` |

### Data Options
| Short Flag | Long Flag | Description | Example |
| :--- | :--- | :--- | :--- |
| `-d` | `--data <data>` | Send URL-encoded data in a POST request | `curl -d "user=a&pass=b" https://target.com/login` |
| | `--data-raw <data>` | Send raw data without interpreting the `@` symbol | `curl --data-raw '{"id":1}' https://api.target.com` |
| | `--data-binary <data>` | Send binary data exactly as-is | `curl --data-binary @payload.json https://api.target.com` |
| | `--data-urlencode <data>` | URL-encode data before sending | `curl --data-urlencode "name=John Doe" https://target.com` |
| `-F` | `--form <name=content>` | Send `multipart/form-data` (use `@` for files) | `curl -F "avatar=@photo.jpg" https://target.com/upload` |
| | `--form-string <name=string>` | Send form data without treating `@` as a file indicator | `curl --form-string "note=@handle" https://target.com` |
| `-T` | `--upload-file <file>` | Upload a local file via PUT | `curl -T shell.php https://target.com/uploads/` |

### Headers
| Short Flag | Long Flag | Description | Example |
| :--- | :--- | :--- | :--- |
| `-H` | `--header <header>` | Add, replace, or remove an HTTP header | `curl -H "Authorization: Bearer TOK" https://target.com` |
| `-A` | `--user-agent <string>` | Set custom User-Agent header | `curl -A "Mozilla/5.0" https://target.com` |
| `-e` | `--referer <URL>` | Set custom Referer header | `curl -e "https://trusted.com" https://target.com` |
| | `--compressed` | Request a compressed response and decompress it | `curl --compressed https://target.com` |

### Authentication
| Short Flag | Long Flag | Description | Example |
| :--- | :--- | :--- | :--- |
| `-u` | `--user <user:password>` | Specify user credentials | `curl -u admin:pass https://target.com` |
| | `--basic` | Force HTTP Basic authentication | `curl --basic -u user:pass https://target.com` |
| | `--digest` | Force HTTP Digest authentication | `curl --digest -u user:pass https://target.com` |
| | `--ntlm` | Force NTLM authentication | `curl --ntlm -u 'DOMAIN\user:pass' https://target.com` |
| | `--negotiate` | Use SPNEGO / Kerberos authentication | `curl --negotiate -u : https://target.com` |
| | `--anyauth` | Ask curl to negotiate the strongest auth method | `curl --anyauth -u user:pass https://target.com` |
| `-E` | `--cert <cert[:passwd]>` | Specify client certificate file (PEM) | `curl -E client.pem:pass https://target.com` |
| | `--key <key>` | Specify private key file | `curl --cert c.crt --key c.key https://target.com` |
| `-n` | `--netrc` | Read credentials from ~/.netrc file | `curl -n https://target.com` |

### Cookies
| Short Flag | Long Flag | Description | Example |
| :--- | :--- | :--- | :--- |
| `-b` | `--cookie <data/file>` | Send cookies as string or load from file | `curl -b "session=abc123" https://target.com` |
| `-c` | `--cookie-jar <file>` | Save received cookies to a file (Netscape format) | `curl -c cookies.txt https://target.com/login` |

### Redirects
| Short Flag | Long Flag | Description | Example |
| :--- | :--- | :--- | :--- |
| `-L` | `--location` | Follow HTTP redirects | `curl -L https://target.com/old` |
| | `--max-redirs <num>` | Set maximum redirect hops | `curl -L --max-redirs 5 https://target.com` |
| | `--location-trusted` | Follow redirects and forward auth/cookies to new host | `curl --location-trusted -u u:p https://target.com` |

### TLS/SSL
| Short Flag | Long Flag | Description | Example |
| :--- | :--- | :--- | :--- |
| `-k` | `--insecure` | Skip TLS certificate verification | `curl -k https://self-signed.local` |
| | `--cacert <file>` | Trust a specific CA certificate bundle | `curl --cacert ca.pem https://internal.target.com` |
| | `--tlsv1.2` / `--tlsv1.3` | Force a minimum TLS version | `curl --tlsv1.2 https://target.com` |
| | `--ciphers <list>` | Restrict the TLS cipher list | `curl --ciphers RC4-SHA https://target.com` |
| | `--cert-status` | Verify server certificate status via OCSP | `curl --cert-status https://target.com` |

### Proxy Settings
| Short Flag | Long Flag | Description | Example |
| :--- | :--- | :--- | :--- |
| `-x` | `--proxy <host:port>` | Route traffic through a proxy (e.g., Burp) | `curl -x http://127.0.0.1:8080 -k https://target.com` |
| `-U` | `--proxy-user <user:pass>`| Specify proxy credentials | `curl -x proxy:8080 -U user:pass https://target.com` |
| | `--socks5 <host:port>` | Route through a SOCKS5 proxy | `curl --socks5 127.0.0.1:9050 https://target.onion` |
| | `--noproxy <hosts>` | List of hosts that bypass the proxy | `curl --noproxy target.com -x proxy:8080 https://target.com` |

### Output Options
| Short Flag | Long Flag | Description | Example |
| :--- | :--- | :--- | :--- |
| `-o` | `--output <file>` | Write response body to a file | `curl -o out.html https://target.com` |
| `-O` | `--remote-name` | Save response to a file named after the remote file | `curl -O https://target.com/report.pdf` |
| `-s` | `--silent` | Mute progress meter and error output | `curl -s https://target.com` |
| `-S` | `--show-error` | Show errors even when running silently | `curl -sS https://target.com` |
| `-i` | `--include` | Include response headers in output | `curl -i https://target.com` |
| `-I` | `--head` | Fetch response headers only (HEAD request) | `curl -I https://target.com` |
| `-w` | `--write-out <format>` | Print custom info after transfer | `curl -o /dev/null -s -w "%{http_code}\n" https://target.com` |
| `-D` | `--dump-header <file>`| Save response headers to a separate file | `curl -D headers.txt https://target.com` |

### Debugging
| Short Flag | Long Flag | Description | Example |
| :--- | :--- | :--- | :--- |
| `-v` | `--verbose` | Output details of request/response headers | `curl -v https://target.com` |
| | `--trace <file>` | Save full hex dump of all incoming/outgoing data | `curl --trace trace.txt https://target.com` |
| | `--trace-ascii <file>` | Save human-readable ASCII trace of data transfer | `curl --trace-ascii trace.txt https://target.com` |
| | `--libcurl <file>` | Generate C code for equivalent libcurl calls | `curl --libcurl code.c https://target.com` |

### Network Configuration
| Short Flag | Long Flag | Description | Example |
| :--- | :--- | :--- | :--- |
| | `--resolve <host:port:address>` | Manually resolve a hostname to a specific IP | `curl --resolve target.com:443:127.0.0.1 https://target.com/` |
| | `--connect-to <host1:port1:host2:port2>` | Redirect connection target without changing Host header | `curl --connect-to target.com:443:staging.internal:443 https://target.com/` |
| | `--interface <name>` | Bind request to a specific network interface | `curl --interface eth0 https://target.com` |
| | `--connect-timeout <seconds>` | Maximum time allowed to establish connection | `curl --connect-timeout 5 https://target.com` |
| `-m` | `--max-time <seconds>` | Maximum time allowed for the entire operation | `curl -m 10 https://target.com` |
| | `--retry <num>` | Number of retries on transient network errors | `curl --retry 3 --retry-delay 2 https://target.com` |
| | `--limit-rate <speed>` | Cap the maximum transfer rate | `curl --limit-rate 200K https://target.com` |

### Automation & Scripting
| Short Flag | Long Flag | Description | Example |
| :--- | :--- | :--- | :--- |
| `-K` | `--config <file>` | Load curl options from a text config file | `curl -K requests.conf` |
| `-Z` | `--parallel` | Perform transfers in parallel | `curl -Z -K urls.conf` |
| `-f` | `--fail` | Fail silently (no body output) on HTTP errors | `curl -f https://target.com/health || echo down` |
| `-g` | `--globoff` | Disable URL globbing (treats `{}[]` literally) | `curl -g "https://target.com/[1-5]"` |
| | `--path-as-is` | Do not resolve `/../` or `/./` in URL path | `curl --path-as-is https://target.com/../../etc/passwd` |

---

## 5. HTTP Methods in Depth

By default, `curl` executes a `GET` request. All other HTTP methods must be explicitly declared using `-X`.

### GET
```bash
curl https://api.target.com/users?id=1
```
> [!NOTE]
> `GET` requests should not contain request bodies. Use `-G` combined with `--data-urlencode` to construct query parameters safely instead of hand-encoding them.

### POST
```bash
curl -X POST https://api.target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"test123"}'
```
> [!TIP]
> Specifying `-d` or `--data` implicitly sets the HTTP method to `POST`. You only need to explicitly write `-X POST` if you are overriding an existing HTTP method selection.

### PUT & PATCH
```bash
# PUT: Implies full-resource replacement
curl -X PUT https://api.target.com/users/42 -H "Content-Type: application/json" -d '{"role":"user"}'

# PATCH: Implies partial modification
curl -X PATCH https://api.target.com/users/42 -H "Content-Type: application/json" -d '{"email":"new@target.com"}'
```
> [!IMPORTANT]
> Backend frameworks frequently handle `PUT` and `PATCH` inconsistently. Testing both methods on the same endpoint is a common way to uncover IDOR or Mass Assignment vulnerabilities.

### DELETE
```bash
curl -X DELETE https://api.target.com/users/42 -H "Authorization: Bearer TOKEN"
```

### HEAD
```bash
curl -I https://target.com
```
Retrieves response headers only (no body). This is ideal for scanning status codes, server banners, and `Content-Length` across multiple endpoints without transferring large assets.

### OPTIONS
```bash
curl -X OPTIONS -i https://api.target.com/admin/users
```
Reads the `Allow` response header. If authentication is configured to protect only `GET` and `POST` methods, but the `Allow` header lists `PUT` or `DELETE`, you may be able to bypass restriction rules.

### TRACE (Cross-Site Tracing risk)
```bash
curl -X TRACE -i https://target.com/
```
If the server echoes your exact request back in the response body (including HTTP headers), the `TRACE` method is enabled. Combined with an XSS vulnerability, this enables **Cross-Site Tracing (XST)**, allowing attackers to access `HttpOnly` cookies.

---

## 6. Sending Data

### Form-encoded (`-d`)
```bash
curl -d "username=admin&password=hunter2" https://target.com/login
```
Automatically sets `Content-Type: application/x-www-form-urlencoded`. Values must be pre-encoded (e.g., spaces as `+` or `%20`).

### Auto URL-encoding
```bash
curl --data-urlencode "comment=hello world & friends" https://target.com/post
```
`curl` performs URL-encoding on your behalf. This prevents characters like `&` and spaces from corrupting field boundaries in the request payload.

### Raw JSON
```bash
curl -X POST https://api.target.com/users \
  -H "Content-Type: application/json" \
  --data-raw '{"name":"test","role":"admin"}'
```
> [!TIP]
> Use `--data-raw` instead of `-d` when your payload might contain a leading `@` symbol. Plain `-d` will interpret a leading `@` as an instruction to load a local file.

### From a File
```bash
curl -X POST https://api.target.com/users -H "Content-Type: application/json" -d @payload.json
```
Useful for large JSON request bodies. Use `--data-binary @file` instead of `-d @file` if you need to preserve exact newlines.

### Multipart / File Upload
```bash
# Basic file upload
curl -F "file=@report.pdf" -F "description=quarterly report" https://target.com/upload

# Force Content-Type header on file upload
curl -F "avatar=@photo.jpg;type=image/jpeg" https://target.com/upload
```
Useful for testing file upload validation bypasses. You can rename file extensions, spoof `type=`, or send binary payloads directly without browser interference.

### PUT a Raw File
```bash
curl -T shell.php https://target.com/uploads/
```

---

## 7. Headers

Customize headers to test authorization controls, bypass filters, or audit security policies.

```bash
curl -H "Authorization: Bearer eyJhbGciOi..." \
  -H "X-Requested-With: XMLHttpRequest" \
  -H "Content-Type: application/json" \
  https://api.target.com/data
```

* **Spoof User-Agent:** Use `-A "Mozilla/5.0 (X11; Linux x86_64)"` to test User-Agent restrictions or bypass simple bot detection.
* **Spoof Referer:** Use `-e "https://trusted-partner.com"` to verify endpoints that rely on Referer validation for origin checking or CSRF protection.
* **Remove default headers:** Provide an empty header definition, e.g. `-H "Host:"` to strip standard headers.
* **Send empty value headers:** Use a trailing semicolon instead of a colon: `-H "X-Custom;"`.
* **Quick Security Header Audit:**
  ```bash
  curl -sI https://target.com | grep -iE "strict-transport|content-security-policy|x-frame|x-content-type"
  ```

---

## 8. Authentication

### Basic / Digest / NTLM
```bash
# Basic Auth (Default)
curl -u admin:password123 https://target.com/admin

# Force Digest Auth
curl --digest -u admin:password123 https://target.com/

# Force NTLM Auth (Windows)
curl --ntlm -u 'DOMAIN\user:pass' https://target.com/

# Auto-negotiation
curl --anyauth -u admin:password https://target.com/
```
> [!TIP]
> Omit the password (e.g., `-u admin:`) to trigger an interactive prompt. This prevents credentials from being exposed in your shell history or process list.

### Bearer Token / JWT
```bash
curl -H "Authorization: Bearer $TOKEN" https://api.target.com/me
```

### Client Certificates (mTLS)
```bash
curl --cert client.crt --key client.key https://internal.target.com/
curl -E client.pem:certpassword https://target.com/
```

### Authentication with `.netrc`
Define credentials in your home directory (`~/.netrc`):
```text
machine target.com login admin password hunter2
```
And execute:
```bash
curl -n https://target.com/secure
```
> [!IMPORTANT]
> The `.netrc` file must have permissions restricted (`chmod 600`) on Unix-like operating systems to prevent other local users from reading it.

---

## 9. Cookies & Sessions

By default, `curl` operates as a stateless client. It ignores incoming cookie headers and does not persist cookies across subsequent requests unless instructed to.

```bash
# Send cookie header manually
curl -b "session=abc123" https://target.com/dashboard

# Write cookies to a file from a login response
curl -c cookies.txt -d "user=admin&pass=test" https://target.com/login

# Read and send saved cookies on a new request
curl -b cookies.txt https://target.com/dashboard

# Full cookie lifecycle: Read and write to the same cookie jar
curl -b cj.txt -c cj.txt https://target.com/step1
curl -b cj.txt -c cj.txt https://target.com/step2
```
> [!NOTE]
> Passing the `-b` flag (even with a non-existent file name) initializes `curl`'s cookie handling engine. This is required if you want redirected requests (`-L`) to propagate cookie changes.

---

## 10. Redirects

```bash
# Follow redirects
curl -L https://target.com/old-path

# Limit maximum redirect count
curl -L --max-redirs 5 https://target.com/

# View redirection chain
curl -v -L https://target.com/ 2>&1 | grep -i location
```
> [!NOTE]
> `curl` does not follow redirects automatically. For open redirect vulnerability assessments, omit `-L` and check the response `Location` header directly.

---

## 11. TLS / SSL

Configure how `curl` handles certificate checks, handshake protocols, and ciphers.

```bash
# Skip certificate verification (Insecure)
curl -k https://self-signed.internal.target.com/

# Trust a specific CA file
curl --cacert corp-ca.pem https://internal.target.com/

# Force minimum TLS protocol version
curl --tlsv1.2 https://target.com/

# Restrict cipher list to audit server configurations
curl --ciphers 'RC4-SHA' https://target.com/

# Inspect SSL certificate information
curl -v https://target.com/ 2>&1 | grep -iE "SSL|subject|issuer"
```

> [!WARNING]
> While `-k` is useful in local development or sandboxed labs, using it on production hosts can mask security misconfigurations (such as invalid CNs, expired certificates, or DNS hijacking).

---

## 12. Proxying (Burp / ZAP Integration)

Route requests through local debugging proxies to analyze, modify, or replay traffic.

```bash
# Route to Burp Suite default listener (127.0.0.1:8080)
curl -x http://127.0.0.1:8080 -k https://target.com/api/data

# Route through SOCKS5 (e.g., Tor network)
curl --socks5 127.0.0.1:9050 https://target.onion/

# Authenticated upstream proxy
curl -x proxy.corp.com:8080 -U proxyuser:proxypass https://target.com/

# Bypass proxy for a specific domain
curl --noproxy "internal.target.com" -x proxy:8080 https://target.com/
```
> [!NOTE]
> `-k` is typically required when routing HTTPS traffic through Burp/ZAP unless you have installed the proxy's CA certificate into your system's trust store.

---

## 13. Output Control & Timing

### Saving Responses
```bash
# Save to custom file name
curl -o out.html https://target.com/

# Save to remote filename automatically
curl -O https://target.com/report.pdf

# Discard body output but show error messages
curl -sS -o /dev/null https://target.com/
```

### Analyzing Connections with `-w` (Write-Out)
The `-w` flag prints detailed diagnostic information after a transfer completes. It is incredibly useful for timing attacks, performance benchmarks, and status sweeps.

```bash
# Print status code only
curl -o /dev/null -s -w "%{http_code}\n" https://target.com/

# Print status code, duration, bytes, and destination IP
curl -o /dev/null -s -w "status:%{http_code} time:%{time_total}s size:%{size_download}b ip:%{remote_ip}\n" https://target.com/

# Connection benchmarks
curl -o /dev/null -s -w "connect:%{time_connect} ttfb:%{time_starttransfer} total:%{time_total}\n" https://target.com/
```

#### Key Formatting Variables
* `%{http_code}`: HTTP response status code.
* `%{time_total}`: Total request duration in seconds.
* `%{time_starttransfer}`: Time to first byte (TTFB) in seconds (useful for measuring response latency).
* `%{size_download}`: Total size of downloaded data in bytes.
* `%{remote_ip}`: Destination IP address (confirms if you are hitting CDN/WAF or origin).
* `%{url_effective}`: Final URL reached (useful after redirects).

---

## 14. Verbose & Debug

To see the exact details of what is transmitted over the wire:

```bash
curl -v https://target.com/
```
#### Output Indicators:
* `*`: Connection events (DNS lookup, TLS details, socket handshake).
* `>`: Sent raw request line and headers.
* `<`: Received raw response line and headers.
* Response body content is displayed without a prefix at the bottom.

### Saving Debug Information
```bash
# Save ASCII log to file
curl --trace-ascii trace.txt https://target.com/

# Read headers only
curl -I https://target.com/
```

---

## 15. Automation & Scripting

### Looping Over a Wordlist
```bash
while read -r path; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$path")
  [ "$code" != "404" ] && echo "$code  /$path"
done < paths.txt
```
> [!NOTE]
> For heavy fuzzing at scale, prefer tools like `ffuf` or `gobuster`. `curl` loops are best suited for dependency-free checks on small lists.

### Concurrency with `xargs`
```bash
cat urls.txt | xargs -P 20 -I{} curl -s -o /dev/null -w "%{http_code} {}\n" {}
```
This runs 20 processes in parallel. It is a quick and effective way to clean crawler lists before executing targeted scans.

### Native Concurrency (curl ≥ 7.66)
Define targets in a configuration file (`urls.conf`):
```text
url = "https://target.com/api/1"
url = "https://target.com/api/2"
url = "https://target.com/api/3"
```
And execute:
```bash
curl -Z --parallel-max 30 -K urls.conf
```

### Parsing JSON Output with `jq`
```bash
curl -s https://api.target.com/users | jq '.[] | select(.role=="admin")'
```

### Global Configuration (`.curlrc`)
Save default parameters to `~/.curlrc` to apply them to every invocation:
```text
-A "Mozilla/5.0 (research)"
-m 15
-sS
```
* **Bypass configuration file:** `curl -q https://target.com/`
* **Load custom config profile:** `curl -K auth-headers.conf https://target.com/`

---

## 16. Security Research Arsenal

> [!CAUTION]
> Ensure you have explicit authorization to audit and test target systems. Unauthorized scanning is illegal.

### Reconnaissance

#### Certificate Transparency Subdomain Harvesting
```bash
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u
```
Pulls subdomains from public certificate logs. No API keys required, no target interaction.

#### Wayback Machine Endpoints Harvest (CDX API)
```bash
curl -s "http://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=text&fl=original&collapse=urlkey" > wayback_urls.txt
```
Discovers historical URL patterns, parameters, and deprecated endpoints.

#### Quick Security Header Inspection
```bash
curl -sI https://target.com | grep -iE "strict-transport-security|content-security-policy|x-frame-options|x-content-type-options|referrer-policy"
```

#### Exposed `.git` / `.env` Checklist
```bash
curl -s -o /dev/null -w "%{http_code}\n" https://target.com/.git/config
curl -s https://target.com/.env
```
Checks for source code exposure or hardcoded secrets.

#### Stack Fingerprinting
```bash
curl -sI https://target.com | grep -iE "server|x-powered-by|x-aspnet-version|x-generator"
```

#### Subdomain Takeover Detection
```bash
curl -sI https://forgotten.target.com | grep -iE "NoSuchBucket|there isn.t a github pages site|herokucdn|fastly"
```
Flags CNAME values pointing to decommissioned external providers.

---

### Exploitation

#### Host Header Injection
```bash
curl -s -H "Host: evil.com" https://target.com/
curl -s -H "X-Forwarded-Host: evil.com" https://target.com/reset-password
```
Tests if the application reflects custom Host headers in redirects or password-reset emails.

#### CORS Misconfiguration Verification
```bash
curl -s -H "Origin: https://evil.com" -I https://target.com/api/account | grep -i "access-control-allow"
```
Checks if arbitrary origins are accepted alongside authentication credentials.

#### Open Redirect Check
```bash
curl -sI "https://target.com/redirect?next=https://evil.com" | grep -i location
```

#### Path Traversal (Disabling Normalization)
```bash
curl --path-as-is https://target.com/static/../../../../etc/passwd
```
> [!IMPORTANT]
> `curl` normally resolves `../` before sending requests. The `--path-as-is` flag is required to verify traversal vulnerabilities.

#### SSRF Payload Injection
```bash
curl "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

#### Verb Tampering & Method Enumeration
```bash
curl -X OPTIONS -i https://target.com/api/admin
curl -X TRACE -i https://target.com/
```

#### JWT Signature Verification Bypass
```bash
curl -H "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ." https://target.com/api/admin
```
Transports tokens constructed with `alg: none` to test signature enforcement.

#### Timing Side-Channel Validation
```bash
curl -s -o /dev/null -w "%{time_starttransfer}\n" -d "username=admin" https://target.com/login
```

---

### Concurrency & Reporting

#### Sweep Active Endpoint Status
```bash
cat urls.txt | xargs -P 20 -I{} curl -s -o /dev/null -w "%{http_code} {}\n" {}
```

#### Native Concurrency Requests
```bash
curl -Z --parallel-max 30 -K urls.conf
```

#### Proof-of-Concept Formatting
```bash
curl -X DELETE https://target.com/api/users/124 -H "Authorization: Bearer <victim_token>"
```
> [!TIP]
> Keep report PoCs minimal. Include only necessary headers and clearly label authorization tokens.

---

### Limitations

#### Request Smuggling Limitations
`curl` is **not** suitable for HTTP request smuggling audits.
```bash
# curl maintains strict compliance for content structures:
# curl automatically computes valid Content-Length and strips illegal formatting.
```
To test CL.TE or TE.CL smuggling, you must control the raw socket bytes using toolsets like `openssl s_client`, `nc`, or Burp's request smuggling plugins.

---

## 17. One-Screen Cheat Sheet

```bash
# --- INSPECTING RESPONSES ---
curl -sI url                      # Headers only (silent)
curl -iL url                      # Headers + Body (follow redirects)
curl -v url 2>&1                  # Full raw verbose log

# --- SENDING DATA ---
curl -X POST -d 'a=1&b=2' url      # URL-encoded POST
curl -H 'Content-Type: application/json' -d '{}' url  # JSON POST
curl -F 'file=@doc.pdf' url       # Multipart file upload

# --- AUTH & SESSIONS ---
curl -u user:pass url             # HTTP Basic Auth
curl -H 'Authorization: Bearer T' url  # Bearer Token Auth
curl -b 'sid=123' url             # Send cookie
curl -c cookies.txt url           # Save cookies

# --- PROXY & TLS ---
curl -x http://127.0.0.1:8080 -k url  # Route through Burp
curl -k url                       # Skip TLS certificate checks
curl --resolve host:443:ip url    # Static hostname resolution override

# --- RECON & AUDITING ---
curl -o /dev/null -s -w '%{http_code}\n' url  # HTTP status only
curl --path-as-is url             # Send un-normalized path (traversal check)
curl -X OPTIONS -i url            # List allowed HTTP methods
curl -A 'UA-string' url           # Custom User-Agent
curl -e 'referer-url' url         # Custom Referer header

# --- RETRY & TIMEOUTS ---
curl -m 10 --connect-timeout 5 url  # Time limits (total: 10s, connect: 5s)
curl -sS -o out.json url          # Suppress status, output to file, print errors
```

---

## Credits & Author Profile

* **Reference Source:** Based on the official curl tutorial ([curl.se/docs/tutorial.html](https://curl.se/docs/tutorial.html)) and real-world security engagements (July 2026).
* **Tool Author:** Daniel Stenberg and the curl project.

### Researcher Profile
* **Researcher:** Sourov Hossen
* **LinkedIn:** [linkedin.com/in/sourov-hossen-307655351](https://linkedin.com/in/sourov-hossen-307655351)
* **GitHub:** [github.com/shii9](https://github.com/shii9)
