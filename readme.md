# c0nscanner

[![python](https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square)](https://python.org)
[![license](https://img.shields.io/badge/license-MIT-green?style=flat-square)](license)
[![platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey?style=flat-square)]()

a comprehensive web vulnerability scanner. inspired by sqlmap, but scans for 11 vulnerability types with a modular plugin architecture.

```
   _____ ___  _ __  ___  ___ __ _ _ __  _ __   ___ _ __
  / __/ _ \| '_ \/ __|/ __/ _` | '_ \| '_ \ / _ \ '__|
 | (_| (_) | | | \__ \ (_| (_| | | | | | | |  __/ |
  \___\___/|_| |_|___/\___\__,_|_| |_|_| |_|\___|_|
                                        v1.0.0
        [ web vulnerability scanner ]
              github.com/k0nnect
```

---

## features

- **11 vulnerability scanners** — sqli, xss, command injection, lfi/rfi, ssrf, security headers, directory enumeration, cors, open redirect, csrf, information disclosure
- **async engine** — built on aiohttp with connection pooling, automatic retries, and rate limiting
- **plugin architecture** — auto-discovering module system, easy to extend with new scanners
- **configurable** — yaml-based config with stealth/aggressive profiles and cli overrides
- **multi-format reports** — json, html (styled dark theme), and text output
- **authentication** — supports basic auth, bearer tokens, and cookie-based sessions
- **proxy support** — route traffic through burp, zap, or any http proxy
- **cross-platform** — runs on windows, linux, and macos

## vulnerability modules

| module | description | techniques |
|--------|-------------|------------|
| `sqli` | sql injection | error-based, blind boolean, time-based, union-based |
| `xss` | cross-site scripting | reflected (context-aware), dom-based analysis |
| `cmdi` | command injection | error-based, time-based blind |
| `lfi` | local/remote file inclusion | path traversal, php wrappers, null byte |
| `ssrf` | server-side request forgery | internal ip, cloud metadata, dns rebinding |
| `headers` | security headers | csp, hsts, x-frame-options, referrer-policy, etc |
| `direnum` | directory enumeration | wordlist-based with smart 404 detection |
| `cors` | cors misconfiguration | origin reflection, null origin, wildcard |
| `openredirect` | open redirects | parameter-based, protocol tricks |
| `csrf` | csrf detection | missing tokens, samesite cookie analysis |
| `infodisclosure` | information disclosure | version leaks, stack traces, secrets in comments |

## installation

```bash
# clone the repo
git clone https://github.com/k0nnect/c0nscanner.git
cd c0nscanner

# install dependencies
pip install -r requirements.txt

# install as a package (optional)
pip install -e .
```

## usage

```bash
# scan a single url
c0nscanner -u "https://example.com/page?id=1"

# scan with all modules, aggressive mode, save all report formats
c0nscanner -u "https://example.com/page?id=1" --aggressive -o report --format all

# scan specific modules only
c0nscanner -u "https://example.com" --modules sqli,xss,headers

# scan with authentication
c0nscanner -u "https://example.com" --cookie "session=abc123"
c0nscanner -u "https://example.com" --auth-type bearer --auth-cred "eyJhbG..."

# stealth mode through a proxy
c0nscanner -u "https://example.com" --stealth --proxy http://127.0.0.1:8080

# scan from a url list
c0nscanner -l urls.txt --threads 20 --format json -o results

# full domain scan
c0nscanner -d example.com --aggressive -o report --format all
```

## cli options

```
options:
  -u, --url TEXT              target url to scan
  -l, --list PATH             file containing list of urls
  -d, --domain TEXT           target domain for full scan
  --modules TEXT              comma-separated modules (default: all)
  --threads INTEGER           concurrent threads (1-50)
  --stealth                   stealth mode (slow, single-threaded)
  --aggressive                aggressive mode (fast, all payloads)
  -o, --output TEXT           output file path (without extension)
  --format [json|html|text|all]  output format
  --config PATH               custom config yaml file
  --cookie TEXT               session cookie string
  --header TEXT TEXT           custom header (name value)
  --auth-type [basic|bearer|cookie]  authentication type
  --auth-cred TEXT            auth credentials
  --proxy TEXT                proxy url
  -v, --verbose               verbose output
  --no-color                  disable colors
  --timeout INTEGER           request timeout (seconds)
  --delay FLOAT               delay between requests (seconds)
  --retries INTEGER           retries per request
  --version                   show version
  -h, --help                  show help
```

## configuration

c0nscanner uses a layered configuration system:

1. **defaults** — `config/default.yaml` (bundled)
2. **user config** — custom yaml via `--config`
3. **cli flags** — highest priority overrides

```yaml
# example custom config
scanner:
  threads: 20
  timeout: 15
  delay: 0.5

modules:
  sqli:
    enabled: true
    techniques: ["error", "time"]
  xss:
    enabled: true
    types: ["reflected"]
  direnum:
    enabled: true
    extensions: [".php", ".html", ".bak"]

output:
  format: "json"
  verbose: true
```

## architecture

```
c0nscanner/
├── c0nscanner/
│   ├── __main__.py          # entry point
│   ├── cli.py               # argument parsing, banner
│   ├── config.py            # layered config management
│   ├── core/
│   │   ├── scanner.py       # scan orchestrator
│   │   ├── http_engine.py   # async http client
│   │   ├── target.py        # url parser
│   │   └── auth.py          # authentication
│   ├── plugins/
│   │   ├── base.py          # plugin base + auto-discovery
│   │   ├── sqli.py          # sql injection
│   │   ├── xss.py           # cross-site scripting
│   │   ├── cmdi.py          # command injection
│   │   ├── lfi.py           # file inclusion
│   │   ├── ssrf.py          # ssrf
│   │   ├── headers.py       # security headers
│   │   ├── direnum.py       # directory enum
│   │   ├── cors.py          # cors misconfig
│   │   ├── openredirect.py  # open redirect
│   │   ├── csrf.py          # csrf
│   │   └── infodisclosure.py # info leaks
│   ├── payloads/            # bundled payload wordlists
│   ├── reporters/           # json, html, text output
│   └── utils/               # colors, logging, helpers
├── config/
│   └── default.yaml         # default configuration
├── requirements.txt
├── setup.py
└── pyproject.toml
```

## extending c0nscanner

create a new plugin by adding a file to `c0nscanner/plugins/`:

```python
from c0nscanner.plugins.base import BasePlugin, Finding

class MyPlugin(BasePlugin):
    name = "myplugin"
    description = "my custom vulnerability scanner"
    default_severity = "medium"

    async def scan(self, target, http):
        findings = []
        # your scanning logic here
        resp = await http.get(target.url)
        if "vulnerable" in resp.body:
            findings.append(self.make_finding(
                title="custom vulnerability found",
                url=target.url,
                evidence="...",
                remediation="...",
            ))
        return findings
```

the plugin is automatically discovered and loaded. enable/disable it in the config:

```yaml
modules:
  myplugin:
    enabled: true
```

## output examples

### terminal output

```
  [*] scanning: https://example.com/page?id=1
    [CRITICAL] error-based sql injection in 'id'
    [HIGH] reflected xss in 'search' (html context)
    [MEDIUM] missing security header: content-security-policy
    [LOW] cookie 'session' missing samesite attribute
    [INFO] version disclosure: apache web server version
```

### html report

the html report features a dark-themed, modern interface with findings grouped by severity, remediation guidance, and reference links.

## disclaimer

this tool is intended for authorized security testing only. always obtain proper permission before scanning any target. unauthorized scanning is illegal. the authors are not responsible for misuse.

## license

mit license. see [license](license) for details.
