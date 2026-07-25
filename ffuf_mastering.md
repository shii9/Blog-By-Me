# Mastering FFUF: The Complete Guide to Web Fuzzing with FFUF (Fuzz Faster U Fool)

![Mastering FFUF Banner](assets/ffuf_mastering.png)

> **A complete guide — from directory brute-forcing to parameter mining, virtual host discovery, and autocalibration.**
>
> *Compiled by **SHIx9** (Sourov Hossen) • 17 min read • Jul 12, 2026*

---

## Table of Contents
1. [What FFUF Actually Is](#01-what-ffuf-actually-is)
2. [Installation](#02-installation)
3. [Core Syntax & the FUZZ Keyword](#03-core-syntax--the-fuzz-keyword)
4. [Directory & File Discovery](#04-directory--file-discovery)
5. [Extension Fuzzing](#05-extension-fuzzing)
6. [Recursive Fuzzing](#06-recursive-fuzzing)
7. [Matchers — Show Results That Match](#07-matchers--show-results-that-match)
8. [Filters — Remove Noise](#08-filters--remove-noise)
9. [Auto-Calibration](#09-auto-calibration)
10. [Parameter Fuzzing](#10-parameter-fuzzing)
11. [Multi-Wordlist Modes](#11-multi-wordlist-modes)
12. [Subdomain & Virtual Host Discovery](#12-subdomain--virtual-host-discovery)
13. [Auth, Headers & Raw Requests](#13-auth-headers--raw-requests)
14. [Threads, Rate & Stealth](#14-threads-rate--stealth)
15. [Proxying & Burp Integration](#15-proxying--burp-integration)
16. [Output & Automation](#16-output--automation)
17. [Config Files & Interactive Mode](#17-config-files--interactive-mode)
18. [Full Flag Reference](#18-full-flag-reference)
19. [Real Methodology — Putting It Together](#19-real-methodology--putting-it-together)
20. [Common Mistakes](#20-common-mistakes)

---

## 01. What FFUF Actually Is

"General-purpose" is the key phrase. FFUF isn't a directory scanner with extra features bolted on—it is a template-substitution engine. You provide it a request template containing a placeholder keyword, and a source of words to substitute into that placeholder. The position of the keyword determines the type of attack you are performing.

> [!NOTE]
> FFUF's core architecture runs each request in its own Goroutine. That is why it scales effortlessly to 40–100+ requests per second without the resource overhead of thread-per-request models.

Two things make it exceptionally fast in practice:
1. **Go's concurrency model:** Each request runs in its own goroutine, scheduled by Go's runtime rather than relying on OS threads directly.
2. **Inline Matcher/Filter engine:** Matcher and filter logic runs inline rather than post-processing, discarding noise on-the-fly instead of dumping thousands of lines for you to search or grep through afterward.

If you only ever run `ffuf -w wordlist -u URL/FUZZ`, you are missing out on the engine's core capabilities: the matcher/filter/autocalibration pipeline and the flexibility to put `FUZZ` anywhere.

---

## 02. Installation

Three primary installation paths are available. Pick the one that best fits your environment:

### Option A — Prebuilt Binary (Fastest)
Grab the latest release for your OS/architecture from GitHub releases, then run:
```bash
chmod +x ffuf
sudo mv ffuf /usr/local/bin/
```

### Option B — Go Install (Requires Go 1.16+)
```bash
go install github.com/ffuf/ffuf/v2@latest
```
*Note: Running this command again at a later date will update the tool to the latest version.*

### Option C — Kali / Debian Package
```bash
sudo apt update && sudo apt install ffuf -y
```

Verify the installation by running:
```bash
ffuf -V
```

On Kali Linux, the standard wordlists live under:
* `/usr/share/seclists/`
* `/usr/share/wordlists/`

*SecLists' `Discovery/Web-Content/` directory is the one you will reach for most often.*

---

## 03. Core Syntax & the FUZZ Keyword

Everything in FFUF revolves around one idea: place the literal string `FUZZ` anywhere in the request URL, header, or POST body. FFUF substitutes each line of your wordlist into that exact position, fires the request, and evaluates the response against your matcher/filter rules.

```bash
ffuf -u https://target.com/FUZZ -w /path/to/wordlist.txt
```

Two flags are mandatory for any run:
* **`-u` (Target URL):** The target that contains `FUZZ` somewhere.
* **`-w` (Wordlist):** The source file to feed the fuzzing engine.

### Custom Keywords
You are not locked to the literal word `FUZZ`. You can attach a custom keyword name to a wordlist with a colon, and reference that keyword in the request. This becomes essential when fuzzing multiple positions simultaneously:

```bash
ffuf -w wordlist.txt:MYKEYWORD -u https://target.com/MYKEYWORD
```

> [!TIP]
> Think of FFUF as "**curl with a for-loop and a decision engine bolted on.**" Anywhere you would place a value in a curl command—the path, a header, or the body—you can drop `FUZZ` instead.

---

## 04. Directory & File Discovery

The most common entry point is enumerating hidden paths on a web server. There is no DNS-style zone transfer equivalent for URL paths, making brute-forcing the only viable discovery method.

```bash
ffuf -u http://target.com/FUZZ \
     -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -mc 200,301,302,403 -fc 404
```

Once a path matches (for example, `/admin` returns a `301`), you can fuzz inside it:

```bash
ffuf -u http://target.com/admin/FUZZ -w admin-panels.txt -mc 200,301,302
```

> [!TIP]
> Wordlist choice is the actual skill. The flag syntax is trivial. What separates a useful scan from noise is using a target-specific list built from JS files, `sitemap.xml`, and `robots.txt` rather than generic wordlists.

---

## 05. Extension Fuzzing

The `-e` flag appends a comma-separated list of extensions to every `FUZZ` substitution. This effectively multiplies your wordlist by the number of extensions provided.

### Fingerprinting default page backend language:
```bash
ffuf -u http://10.201.83.65/indexFUZZ \
     -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt
```
This fuzzes the extension directly onto `index`, helping identify which server-side language is behind the default page (`.php`, `.asp`, `.jsp`, etc.) without guessing.

### Standard extension fuzzing:
```bash
ffuf -u http://10.201.83.65/FUZZ \
     -w wordlist.txt -e .php,.bak,.txt,.old
```
This tries every wordlist entry both bare and with each extension appended (e.g., `admin`, `admin.php`, `admin.bak`, `admin.txt`, `admin.old`).

### DirSearch Compatibility Mode
If you are reusing wordlists built for dirsearch that contain the `%EXT%` placeholder token, pass `-D` alongside `-e`. FFUF then replaces `%EXT%` with each extension instead of blindly appending.

```bash
ffuf -u http://target.com/FUZZ \
     -w dirsearch-wordlist.txt -e php,bak -D
```

> [!IMPORTANT]
> DirSearch compatibility mode (`-D`) is critical when using wordlists containing `%EXT%` placeholders, ensuring FFUF replaces the placeholder instead of blindly appending at the end of the line.

---

## 06. Recursive Fuzzing

Recursion means that when a discovered path looks like a directory, FFUF automatically kicks off a new fuzzing job inside it. The URL passed to `-u` must end in the `FUZZ` keyword for recursion to function.

```bash
ffuf -u http://target.com/FUZZ \
     -w /usr/share/seclists/Discovery/Web-Content/common-dirs.txt \
     -recursion -recursion-depth 2 \
     -mc 200,301 -fc 404 \
     -t 20 -o ffuf_rec.json -of json
```

* **`-recursion`:** Enable recursive scanning (default: off).
* **`-recursion-depth`:** Maximum depth level. `0` means unlimited (dangerous on large targets).
* **`-recursion-strategy`:**
  * `default`: Recurses only on redirect responses (e.g., a `301` to a trailing slash implies a directory).
  * `greedy`: Recurses into any matched result. This finds more but multiplies request volume rapidly.

```bash
# Greedy strategy example - recurse into every match, not just redirects
ffuf -u http://target.com/FUZZ -w common-dirs.txt \
     -recursion -recursion-depth 2 -recursion-strategy greedy -mc 200,301
```

> [!WARNING]
> Recursion depth compounds request volume. A wordlist of 5,000 words at depth 2 with even a handful of matched directories can spawn tens of thousands of requests. Always pair recursion with tight matchers/filters and a sane `-recursion-depth`.

---

## 07. Matchers — Show Results That Match

Matchers are an inclusion list: only responses satisfying at least one matcher condition are shown (OR logic by default, configurable via `-mmode`).

* **`-mc`:** Match by HTTP status code. Default: `200,204,301,302,307,401,403,405,500`. Use `all` to match everything.
  ```bash
  ffuf -u http://target.com/FUZZ -w wordlist.txt -mc 200,301,302
  ```
* **`-ms`:** Match by response size in bytes.
  ```bash
  ffuf -u http://target.com/FUZZ -w wordlist.txt -ms 1024-2048
  ```
* **`-mw`:** Match by word count in the response body.
  ```bash
  ffuf -u http://target.com/FUZZ -w wordlist.txt -mw 0,100-500
  ```
* **`-ml`:** Match by line count in the response body.
  ```bash
  ffuf -u http://target.com/FUZZ -w wordlist.txt -ml 3,10-20
  ```
* **`-mr`:** Match against a regex on the response body.
  ```bash
  ffuf -u http://target.com/FUZZ -w wordlist.txt -mr 'Welcome, [A-Za-z]+'
  ```
* **`-mt`:** Match by time-to-first-byte in milliseconds, using `>` or `<`. Useful for blind, time-based SQL injection detection.
  ```bash
  ffuf -u "http://target.com/search?q=FUZZ" -w sqli-payloads.txt -mt ">4000"
  ```
* **`-mmode`:** Set operator across matcher rules: `or` (default) or `and`.
  ```bash
  ffuf -u http://target.com/FUZZ -w wordlist.txt -mc 200 -ms 500-2000 -mmode and
  ```

> [!TIP]
> `-mr` (regex matching) is incredibly powerful. Use it to catch reflected values, debug strings, stack traces, or app-specific success markers that a status code alone will not reveal.

---

## 08. Filters — Remove Noise

Filters are the inverse of matchers: an exclusion list. Anything matching a filter condition gets dropped from the output, regardless of matcher rules.

* **`-fc`:** Filter out by status code.
  ```bash
  ffuf -u http://target.com/FUZZ -w wordlist.txt -fc 404,302
  ```
* **`-fs`:** Filter out by response size.
  ```bash
  ffuf -u http://target.com/FUZZ -w wordlist.txt -fs 4242,1024-2048
  ```
* **`-fw`:** Filter out by word count.
  ```bash
  ffuf -u http://target.com/FUZZ -w wordlist.txt -fw 0,50-60
  ```
* **`-fl`:** Filter out by line count.
  ```bash
  ffuf -u http://target.com/FUZZ -w wordlist.txt -fl 20-30
  ```
* **`-fr`:** Filter out anything matching a regex on the response body.
  ```bash
  ffuf -u http://target.com/FUZZ -w wordlist.txt -fr '/\..*'
  ```
* **`-ft`:** Filter out by time-to-first-byte, using `>` or `<`.
  ```bash
  ffuf -u http://target.com/FUZZ -w wordlist.txt -ft ">5000"
  ```
* **`-fmode`:** Set operator across filter rules: `or` (default) or `and`.
  ```bash
  ffuf -u http://target.com/FUZZ -w wordlist.txt -fs 4242 -fw 22 -fmode and
  ```

### Matchers vs. Filters: When to use which?
* **Filters** are for known noise: a soft-404 page that always returns the same size, a WAF block page, or a status code you already know is irrelevant.
* **Matchers** are for known targets: you know what "success" looks like before scanning (e.g., only `200`s and `301`s, or a specific regex).

---

## 09. Auto-Calibration

Autocalibration automates the process of identifying and filtering noise. Before the real scan starts, FFUF sends a handful of requests using random, non-existent paths, records the response signature (size, word count, status), and automatically builds filters to exclude them. This solves the "soft 404" problem.

```bash
ffuf -u http://target.com/FUZZ -w wordlist.txt -ac
```

* **`-ach` (Per-Host Auto-Calibration):** Recalibrates separately for each distinct host. Crucial when fuzzing across multiple targets or vhosts in one run.
  ```bash
  ffuf -u https://FUZZH.target.com/FUZZ -w hosts.txt:FUZZH -w common.txt:FUZZ -ach
  ```
* **`-ack`:** Customize the placeholder value FFUF probes with.
  ```bash
  ffuf -u http://target.com/FUZZ -w wordlist.txt -ac -ack "randomtest123"
  ```
* **`-acc`:** Supply your own custom calibration strings instead of relying on FFUF's random probes.
  ```bash
  ffuf -u http://target.com/FUZZ -w wordlist.txt -acc "nonexistent1,nonexistent2"
  ```

> [!WARNING]
> Autocalibration fails when the `FUZZ` keyword is embedded in a hostname rather than a path. A nonsense hostname will not resolve. When fuzzing hostnames via `-w hosts.txt:HOST -u https://HOST/`, skip `-ac` and filter manually with `-fs`/`-fw`.

---

## 10. Parameter Fuzzing

Parameter fuzzing generally involves two distinct tasks: finding parameter names that an endpoint accepts versus finding parameter values once you know the name.

### Finding parameter names (GET)
Use a placeholder value (`test`) and place `FUZZ` where the parameter name goes. A response that differs in size or status from the baseline signals a valid parameter.
```bash
ffuf -u "https://target.com/search.php?FUZZ=test" \
     -w params.txt -mc 200,302 -fc 404 \
     -t 40 -o out.json -of json
```

### Finding parameter values
Once the parameter name is known, place `FUZZ` where the value goes:
```bash
ffuf -u "https://target.com/search.php?test=FUZZ" \
     -w params.txt -mc 200,302 -fc 404
```

### Isolating error-revealing responses
Instead of guessing status codes, search for specific text patterns returned when a valid parameter name is processed:
```bash
ffuf -u "https://target.com/search.php?FUZZ=test" \
     -w params.txt -mr "Invalid|No such|Exception|token|required"
```

### POST parameter fuzzing (Form-Encoded)
```bash
ffuf -u "https://target.com/account/settings" -X POST \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "username=admin&FUZZ=1" \
     -w params.txt -mc 200,302 -fs 1024
```

### POST parameter fuzzing (JSON Body)
```bash
ffuf -u "https://api.target.com/v1/resource" -X POST \
     -H "Content-Type: application/json" \
     -d '{"FUZZ":"test"}' \
     -w params.txt
```

### Fuzzing multiple positions
```bash
ffuf -u "https://target.com/FUZZ.php?FUZZ2=test" \
     -w pnames.txt:FUZZ -w pnames2.txt:FUZZ2 -t 20
```

> [!IMPORTANT]
> FFUF does not automatically set request headers based on your `-d` payload content. Sending JSON without an explicit `-H "Content-Type: application/json"` header will likely cause the server to reject the request, resulting in false negatives.

---

## 11. Multi-Wordlist Modes

When more than one `-w` is supplied (each with its own keyword), `-mode` controls how they are combined.

* **`clusterbomb` (Default):** Every combination of every wordlist is tried (a full cross product).
  * **Request Count:** `len(W1) * len(W2) * ...`
  ```bash
  ffuf -request brute.txt -request-proto http \
       -mode clusterbomb \
       -w users.txt:HFUZZ -w pass.txt:WFUZZ -mc 200
  ```
* **`pitchfork`:** Wordlists are stepped through in lockstep (line N of W1 paired with line N of W2).
  * **Request Count:** `min(len(W1), len(W2), ...)`
  ```bash
  ffuf -u https://target.com/login -X POST \
       -d "user=USERFUZZ&pass=PASSFUZZ" \
       -w users.txt:USERFUZZ -w passwords.txt:PASSFUZZ \
       -mode pitchfork
  ```
* **`sniper`:** Fuzzes one keyword position at a time while holding others static. Useful for isolating which position triggers a behavior change.
  * **Request Count:** `sum(len(W1), len(W2), ...)`
  ```bash
  ffuf -u "https://target.com/FUZZ1/FUZZ2" \
       -w path1.txt:FUZZ1 -w path2.txt:FUZZ2 \
       -mode sniper
  ```

> [!CAUTION]
> `clusterbomb` mode scales exponentially. Two 10,000-line wordlists in `clusterbomb` mode require 100,000,000 requests. Verify your request count before running. Use `pitchfork` for paired credentials.

---

## 12. Subdomain & Virtual Host Discovery

HTTP/1.1's `Host` header tells the server which virtual host you want. Since many servers host multiple domains on a single IP (name-based virtual hosting), Host-header fuzzing is a powerful technique for discovering internal applications, staging sites, and admin panels with no public DNS records.

### DNS-Resolvable Subdomain Fuzzing
```bash
ffuf -u http://FUZZ.target.com \
     -w subdomains.txt -t 10 --delay 150ms -mc 200,301
```

### Host-Header-Based Subdomain Fuzzing (No DNS resolution required)
```bash
ffuf -u https://target/ -H "Host: FUZZ.target.com" \
     -w subdomains.txt -t 10 --delay 150ms -mc 200,301
```

### Virtual Host Discovery (Against a raw IP)
Points every request at the same IP while varying the Host header:
```bash
ffuf -u http://10.10.10.10/ \
     -H "Host: FUZZ.company.com" \
     -w subdomains.txt -mc 200,301,302 -fs 4242
```
*Here, `-fs 4242` filters out the default virtual host's response size, revealing only unique vhosts.*

### Verifying a candidate manually:
```bash
curl -I -s -k -H "Host: found.target.com" https://10.10.10.10/
```

---

## 13. Auth, Headers & Raw Requests

### Cookies, Headers, and Tokens
```bash
ffuf -u https://target.com/FUZZ -w wordlist.txt \
     -H "Authorization: Bearer <token>" \
     -b "session=abcd1234; theme=dark"
```
*Note: `-H` can be repeated to send multiple headers, and `FUZZ` can live inside header values.*

### Fuzzing a header value directly:
```bash
ffuf -u https://target.com/ -w ip-list.txt \
     -H "X-Forwarded-For: FUZZ" -mc 200
```

### Client Certificates (mTLS)
Pass both `-cc` (client cert) and `-key` (client key):
```bash
ffuf -u https://target.com/FUZZ -w wordlist.txt \
     -cc client.pem -ck client.key
```

### Raw Request Files (Recommended)
Instead of reconstructing headers and cookies by hand, copy the raw request from Burp Suite (Right-click -> Copy to file) and pass it directly to FFUF. Insert the `FUZZ` keyword where needed.

```bash
ffuf -request raw_req.txt -request-proto https -w wordlist.txt
```

> [!TIP]
> Raw request files cannot encode the scheme (HTTP vs HTTPS). You must explicitly define this using `-request-proto` when auditing HTTPS targets.

---

## 14. Threads, Rate & Stealth

Concurrency and pacing determine both scan speed and detectability.

* **`-t`:** Concurrent worker threads (default: 40).
  ```bash
  ffuf -u http://target.com/FUZZ -w wordlist.txt -t 100
  ```
* **`-p`:** Delay in seconds between requests. Can be a range to add jitter and bypass rate-limiting WAF rules.
  ```bash
  ffuf -u http://target.com/FUZZ -w wordlist.txt -p 0.1-0.5
  ```
* **`-rate`:** Global cap on requests per second (RPS).
  ```bash
  ffuf -u http://target.com/FUZZ -w wordlist.txt -rate 20
  ```
* **`-timeout`:** Per-request timeout in seconds (default: 10).
  ```bash
  ffuf -u http://target.com/FUZZ -w wordlist.txt -timeout 5
  ```
* **`-maxtime`:** Hard ceiling on total run time.
  ```bash
  ffuf -u http://target.com/FUZZ -w wordlist.txt -maxtime 600
  ```
* **`-maxtime-job`:** Hard ceiling per individual job (useful for keeping recursive jobs bounded).
  ```bash
  ffuf -u http://target.com/FUZZ -w wordlist.txt -recursion -maxtime-job 120
  ```

### Concurrency Reference

| Thread Count | Mode | Recommended Scenario |
| :--- | :--- | :--- |
| **1–10** | Stealthy | WAF-protected or rate-limited targets |
| **10–40** | Balanced | Default for authorized engagements |
| **50–200** | Aggressive | Local labs, CTFs, or robust infrastructure |
| **300+** | Self-DoS Risk | **Not recommended** for production environments |

### Early-Exit Controls
* **`-sf`:** Stop automatically once ~95% of responses return `403` (indicates a WAF block).
* **`-se`:** Stop on spurious/transient network errors (timeouts, connection resets).
* **`-sa`:** Stop on all error conditions (strict combination of `-sf` and `-se`).

---

## 15. Proxying & Burp Integration

You can route all traffic through an intercepting proxy, or route only matched hits for manual review.

### Route all requests through Burp (Slower, full visibility):
```bash
ffuf -u http://target.com/FUZZ -w wordlist.txt -x http://127.0.0.1:8080
```

### Route ONLY matches through Burp (Recommended):
Run the scan at full speed directly, and replay only successful matches through Burp Suite for manual verification. This keeps proxy history clean and prevents Burp from lagging.

```bash
ffuf -u http://target.com/FUZZ -w wordlist.txt \
     -replay-proxy http://127.0.0.1:8080
```

---

## 16. Output & Automation

Save your results to a file for parsing, reporting, or piping into other tools:

```bash
ffuf -u https://target.com/FUZZ -w wordlist.txt -o results.json -of json
```

### Available Output Formats
* **`json` (Default):** Easily parsed with `jq` for automation.
* **`ejson`:** Extended JSON, including full request/response metadata.
* **`html`:** Rendered report for documentation.
* **`md`:** Markdown format, perfect for notes and writeups.
* **`csv` / `ecsv`:** Spreadsheet format; `ecsv` escapes fields safely for Excel.
* **`all`:** Writes all formats simultaneously.

### Real-Time Pipeline Parsing
Pass `-json` to format stdout as newline-delimited JSON. You can pipe this live stream directly into other processes (like `jq`):

```bash
ffuf -u https://target.com/FUZZ -w wordlist.txt -json | jq -c 'select(.status==200)'
```

### Saving Response Bodies
Use `-od` to write each matched response body to its own file in a specified directory:
```bash
ffuf -u https://target.com/FUZZ -w wordlist.txt -od responses/
```

---

## 17. Config Files & Interactive Mode

### Persistent Defaults via `ffufrc`
FFUF automatically loads `$XDG_CONFIG_HOME/ffuf/ffufrc` (or `~/.config/ffuf/ffufrc`) if it exists. Command-line flags override these defaults, except for repeatable flags like `-H`, which append to the configuration.

```bash
# Run using a specific engagement config file
ffuf -config /path/to/engagement.conf -u https://target.com/FUZZ -w wordlist.txt
```

### Interactive Mode (Pause & Reconfigure)
Press `ENTER` during a running scan to drop into an interactive console without killing the job:

* `fc / fl / fw / fs [value]` — Reconfigure filters on the fly.
* `show` — Print all current matches discovered under the new filter state.
* `queueshow / queuedel / queueskip` — Manage recursive jobs in the queue.
* `restart` — Reset and restart the current job from scratch (useful if you over-filtered).
* `resume` — Resume the paused job.
* `savejson [filename]` — Dump current matches to a JSON file mid-run.

---

## 18. Full Flag Reference

### HTTP Options
| Flag | Description | Example |
| :--- | :--- | :--- |
| `-u <URL>` | Target URL, must contain the keyword `FUZZ` | `-u http://target.com/FUZZ` |
| `-X <method>` | HTTP method to use | `-X POST` |
| `-H <header>` | HTTP header, repeatable | `-H "Authorization: Bearer Token"` |
| `-b <cookie>` | Cookie data | `-b "session=abc"` |
| `-d <data>` | Request body data | `-d "username=admin"` |
| `-r` | Follow redirects | `-r` |
| `-x <proxy>` | Proxy URL (HTTP/SOCKS5) | `-x http://127.0.0.1:8080` |
| `-replay-proxy <proxy>` | Proxy for replaying matched requests only | `-replay-proxy http://127.0.0.1:8080` |
| `-cc <cert>` | Client certificate for mTLS | `-cc client.pem` |
| `-ck <key>` | Client key for mTLS | `-ck client.key` |
| `-raw` | Do not URI-encode the request | `-raw` |
| `-timeout <sec>` | Per-request timeout in seconds | `-timeout 5` |
| `-recursion` | Enable recursive scanning | `-recursion` |
| `-recursion-depth <depth>` | Maximum recursion depth | `-recursion-depth 2` |
| `-recursion-strategy <strat>`| Strategy: `default` or `greedy` | `-recursion-strategy greedy` |
| `-ignore-body` | Skip fetching response body content | `-ignore-body` |
| `-http2` | Use HTTP/2 | `-http2` |
| `-sni <value>` | Target TLS SNI value | `-sni target.com` |

### General Options
| Flag | Description | Example |
| :--- | :--- | :--- |
| `-t <threads>` | Thread count (default: 40) | `-t 100` |
| `-p <delay>` | Delay between requests in seconds (e.g. `0.1` or `0.1-0.5`) | `-p 0.1-0.3` |
| `-rate <rps>` | Global rate limit cap in requests per second | `-rate 50` |
| `-maxtime <sec>` | Total run time ceiling | `-maxtime 300` |
| `-maxtime-job <sec>` | Run time ceiling per individual job | `-maxtime-job 60` |
| `-c` | Colorize CLI output | `-c` |
| `-v` | Verbose output | `-v` |
| `-s` | Silent/quiet mode | `-s` |
| `-ac` | Auto-calibration | `-ac` |
| `-ach` | Per-host auto-calibration | `-ach` |
| `-ack <string>` | Auto-calibration probe string | `-ack "test"` |
| `-acc <string>` | Custom auto-calibration strings | `-acc "err1,err2"` |
| `-sf` | Stop on WAF detection (~95% 403s) | `-sf` |
| `-se` | Stop on spurious network errors | `-se` |
| `-sa` | Stop on all error conditions | `-sa` |
| `-noninteractive` | Disable interactive console | `-noninteractive` |
| `-json` | Print JSON live output | `-json` |
| `-V` | Version info | `-V` |
| `-config <path>` | Custom config file path | `-config ffufrc.conf` |

### Input Options
| Flag | Description | Example |
| :--- | :--- | :--- |
| `-w <path>` | Wordlist path (optional format: `path:KEYWORD`) | `-w wordlist.txt:FUZZ` |
| `-e <extensions>` | Extension list to append to FUZZ | `-e .php,.txt` |
| `-D` | DirSearch compatibility mode | `-D` |
| `-enc <encoders>` | Encoders for keyword values | `-enc url` |
| `-ic` | Ignore wordlist comments | `-ic` |
| `-mode <mode>` | Multi-wordlist mode (`clusterbomb`, `pitchfork`, `sniper`) | `-mode pitchfork` |
| `-input-cmd <cmd>` | Command to generate input dynamically | `-input-cmd "cat wordlist"` |
| `-input-num <num>` | Number of inputs to generate dynamically | `-input-num 100` |
| `-input-shell <shell>`| Shell to run the input command in | `-input-shell bash` |
| `-request <path>` | Raw HTTP request file | `-request req.txt` |
| `-request-proto <proto>` | Protocol for raw request (`http` or `https`) | `-request-proto https` |

### Matcher Options
| Flag | Description | Example |
| :--- | :--- | :--- |
| `-mc <codes>` | Match status codes | `-mc 200,301` |
| `-ms <size>` | Match response size | `-ms 100-200` |
| `-mw <words>` | Match word count | `-mw 20` |
| `-ml <lines>` | Match line count | `-ml 10-15` |
| `-mr <regex>` | Match regex in response body | `-mr "admin"` |
| `-mt <time>` | Match time-to-first-byte (e.g. `>4000`) | `-mt ">5000"` |
| `-mmode <mode>` | Matcher set operator (`or`/`and`) | `-mmode and` |

### Filter Options
| Flag | Description | Example |
| :--- | :--- | :--- |
| `-fc <codes>` | Filter status codes | `-fc 404,500` |
| `-fs <size>` | Filter response size | `-fs 4242` |
| `-fw <words>` | Filter word count | `-fw 0` |
| `-fl <lines>` | Filter line count | `-fl 2` |
| `-fr <regex>` | Filter regex on response body | `-fr "blocked"` |
| `-ft <time>` | Filter time-to-first-byte | `-ft ">3000"` |
| `-fmode <mode>` | Filter set operator (`or`/`and`) | `-fmode and` |

### Output Options
| Flag | Description | Example |
| :--- | :--- | :--- |
| `-o <file>` | Output file path | `-o results.json` |
| `-of <format>` | Output format (`json`, `ejson`, `html`, `md`, `csv`, `ecsv`, `all`) | `-of html` |
| `-od <dir>` | Directory for per-result response bodies | `-od matched_responses/` |
| `-or` | Skip output file creation if no results | `-or` |
| `-debug-log <file>`| Internal logging file | `-debug-log debug.log` |
| `-audit-log <file>`| Full request/response audit log | `-audit-log audit.log` |

---

## 19. Real Methodology — Putting It Together

A standard web application engagement follows these steps:

1. **Baseline the Target:** Run a wide-open scan with default matchers, no filters, and a small thread count. Identify the response signature of non-existent endpoints (size, status code, word count). This determines if the server uses soft-404s and whether auto-calibration is viable.
2. **Directory & File Discovery:** Perform a path scan using `-ac` or manually defined `-fs`/`-fc` filters. Use a tech-stack specific wordlist and append relevant extensions via `-e`. Save results in JSON format using `-o`.
3. **Selectively Recurse:** Do not recurse blindly across the entire target. Select directories that return interesting status codes (like `200` or `403`) and run targeted recursive scans with a bounded depth limit.
4. **Parameter Mining:** Once valid endpoints are confirmed, fuzz for accepted parameters. Use `-mr` to match app-specific error messages or database exceptions rather than relying on HTTP status codes.
5. **Subdomain / VHost Sweep:** Conduct a separate subdomain sweep. If targeting multiple Virtual Hosts hosted on the same IP address, use `-ach` (per-host auto-calibration).
6. **Replay Matches to Proxy:** Use `-replay-proxy` during discovery so that only verified matches are forwarded to Burp Suite. This keeps your Burp history uncluttered and keeps analysis focused.

---

## 20. Common Mistakes

* **Omitting Content-Type Headers:** Sending JSON request bodies via `-d` without declaring `-H "Content-Type: application/json"`. The server will likely reject the request as malformed before processing the input.
* **Unbounded Clusterbomb Scans:** Combining two large wordlists in `clusterbomb` mode without calculating the request count beforehand.
* **Unconstrained Recursion:** Enabling `-recursion` with depth `0` and no time limits (`-maxtime`), causing the scanner to get stuck in infinite routing loops on dynamic websites.
* **Auto-Calibration on Hostnames:** Enabling `-ac` when the `FUZZ` keyword is positioned in the hostname. The DNS resolver fails to resolve the random auto-calibration domains, resulting in task termination.
* **Aggressive Threading:** Running high thread counts (`-t 200+`) against WAF-protected or rate-limited endpoints. This triggers defensive blocking and degrades scan accuracy.
* **Ignoring Protocol on Raw Requests:** Forgetting to pass `-request-proto https` when importing raw request text files for HTTPS targets.

---

## Researcher Profile

* **Researcher:** Sourov Hossen
* **LinkedIn:** [linkedin.com/in/sourov-hossen-307655351](https://linkedin.com/in/sourov-hossen-307655351)
* **GitHub:** [github.com/shii9](https://github.com/shii9)
