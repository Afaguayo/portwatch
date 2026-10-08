# portwatch

[![CI](https://github.com/Afaguayo/portwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/Afaguayo/portwatch/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.23%2B-00ADD8)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A fast, concurrent TCP port scanner written in Go, with banner grabbing and
TLS certificate expiry checks. Built for auditing **your own** hosts — a
home lab, a VPS, a CI-provisioned test environment.

> ⚠️ **Only scan hosts you own or are explicitly authorized to test.**
> Unauthorized scanning of systems you don't control may be illegal in your
> jurisdiction (e.g. under the US Computer Fraud and Abuse Act or similar
> laws elsewhere). This tool is for defensive auditing and learning.

## Download

Prebuilt binaries (Linux, macOS, Windows `.exe`) are published on every
tagged release: **[Download the latest release](https://github.com/Afaguayo/portwatch/releases/latest)**.

## Why

`nmap` does this and more, but a small Go scanner is a good systems-
programming exercise and a handy single-binary tool to drop on a box with
no package manager access. `portwatch` focuses on three things nmap users
reach for constantly: is the port open, what's the banner, and (for 443)
how long until the cert expires.

## How it works

- **Target parsing**: `-hosts` accepts a comma-separated mix of plain
  hosts/IPs and CIDR blocks (`10.0.0.0/28` expands to every usable address,
  dropping network/broadcast). `-ports` accepts single ports and ranges
  (`22,80,8000-8010`).
- **Worker pool**: all host×port combinations are pushed onto a job
  channel consumed by `-concurrency` goroutines (default 100), each doing a
  `net.DialTimeout`. This is what makes scanning a `/24` in seconds instead
  of minutes.
- **Banner grab**: on a successful connect, read whatever the service sends
  first (SSH, FTP, SMTP banners etc. all send a greeting unprompted), with
  a short read deadline so it doesn't hang on silent services.
- **TLS expiry check**: for port 443, opens a TLS connection, reads the
  leaf certificate, and reports the issuer, expiry date, and days
  remaining (negative = already expired).

## Build from source

Requires Go 1.23+.

```bash
go build -o portwatch ./cmd/portwatch
```

## Usage

```bash
./portwatch -hosts 192.168.1.10 -ports 22,80,443
```

```
Scanning 1 host(s) x 3 port(s) with 100 workers...
HOST                 PORT   STATE  BANNER                         TLS
192.168.1.10         22     open   SSH-2.0-OpenSSH_9.6
192.168.1.10         443    open                                  expires 2027-03-01 (144d) issuer=R3

1 open port(s) found.
```

Scan a whole subnet you own, wider port range, more workers:

```bash
./portwatch -hosts 10.0.0.0/28 -ports 1-1024 -concurrency 300
```

Machine-readable output:

```bash
./portwatch -hosts example.com -ports 443 -json
```

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `-hosts` | *(required)* | Comma-separated hosts/IPs and/or CIDR blocks |
| `-ports` | `22,80,443` | Comma-separated ports and/or ranges |
| `-concurrency` | 100 | Worker pool size |
| `-timeout-ms` | 2000 | Per-connection timeout |
| `-json` | off | JSON output |
| `-open-only` | true | Hide closed ports (set `=false` to see everything) |
| `-no-banner` | off | Skip banner grabbing |
| `-no-tls` | off | Skip TLS expiry checks |

## Tests

```bash
go test ./... -v
```

14 tests: target/port parsing (CIDR expansion, ranges, de-duplication,
validation) and the scanner engine itself against real local TCP listeners
on loopback (no external network calls) — open detection, closed
detection, banner capture, and sanitization.

## Limitations

- No SYN/stealth scanning — this is a full TCP connect scan, which is
  louder but needs no raw-socket privileges.
- UDP is not supported.
- TLS check only runs automatically on port 443; other TLS ports need
  `-no-tls=false` logic extended (contributions welcome).

## License

MIT — see [LICENSE](LICENSE).
