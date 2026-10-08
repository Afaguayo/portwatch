// Command portwatch is a concurrent TCP port scanner with banner grabbing
// and TLS certificate expiry checks.
//
// IMPORTANT: only use this against hosts you own or are explicitly
// authorized to test. Scanning systems without permission may be illegal
// in your jurisdiction.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Afaguayo/portwatch/internal/scanner"
)

func main() {
	hostsFlag := flag.String("hosts", "", "Comma-separated hosts and/or CIDR blocks, e.g. 192.168.1.10,10.0.0.0/28")
	portsFlag := flag.String("ports", "22,80,443", "Comma-separated ports and/or ranges, e.g. 22,80,443,8000-8010")
	concurrency := flag.Int("concurrency", 100, "Number of concurrent workers")
	timeoutMs := flag.Int("timeout-ms", 2000, "Per-connection timeout in milliseconds")
	jsonOut := flag.Bool("json", false, "Emit JSON instead of a text table")
	openOnly := flag.Bool("open-only", true, "Only print open ports (set -open-only=false to see closed too)")
	noBanner := flag.Bool("no-banner", false, "Skip banner grabbing")
	noTLS := flag.Bool("no-tls", false, "Skip TLS certificate expiry checks on port 443")

	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, `portwatch - concurrent TCP port scanner with banner grab + TLS expiry check

  Only scan hosts you own or are authorized to test.

Usage:
  portwatch -hosts <hosts> [-ports <ports>] [options]

Examples:
  portwatch -hosts 192.168.1.10 -ports 22,80,443
  portwatch -hosts 10.0.0.0/28 -ports 1-1024 -concurrency 200
  portwatch -hosts example.com -ports 443 -json

Options:`)
		flag.PrintDefaults()
	}
	flag.Parse()

	if *hostsFlag == "" {
		fmt.Fprintln(os.Stderr, "Error: -hosts is required.")
		flag.Usage()
		os.Exit(1)
	}

	hosts, err := scanner.ParseHosts(*hostsFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	ports, err := scanner.ParsePorts(*portsFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	opts := scanner.Options{
		Concurrency: *concurrency,
		Timeout:     time.Duration(*timeoutMs) * time.Millisecond,
		GrabBanner:  !*noBanner,
		CheckTLS:    !*noTLS,
	}

	fmt.Fprintf(os.Stderr, "Scanning %d host(s) x %d port(s) with %d workers...\n", len(hosts), len(ports), opts.Concurrency)
	results := scanner.Scan(hosts, ports, opts)

	if *jsonOut {
		printJSON(results, *openOnly)
	} else {
		printTable(results, *openOnly)
	}
}

func printTable(results []scanner.Result, openOnly bool) {
	openCount := 0
	fmt.Printf("%-20s %-6s %-6s %-30s %s\n", "HOST", "PORT", "STATE", "BANNER", "TLS")
	for _, r := range results {
		if openOnly && !r.Open {
			continue
		}
		if r.Open {
			openCount++
		}
		state := "closed"
		if r.Open {
			state = "open"
		}
		tlsInfo := ""
		if r.TLSExpiry != nil {
			if r.TLSExpiry.Expired {
				tlsInfo = fmt.Sprintf("EXPIRED %s", r.TLSExpiry.NotAfter.Format("2006-01-02"))
			} else {
				tlsInfo = fmt.Sprintf("expires %s (%dd) issuer=%s",
					r.TLSExpiry.NotAfter.Format("2006-01-02"), r.TLSExpiry.DaysRemaining, r.TLSExpiry.Issuer)
			}
		}
		fmt.Printf("%-20s %-6d %-6s %-30s %s\n", r.Host, r.Port, state, truncate(r.Banner, 30), tlsInfo)
	}
	fmt.Printf("\n%d open port(s) found.\n", openCount)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func printJSON(results []scanner.Result, openOnly bool) {
	var filtered []scanner.Result
	for _, r := range results {
		if openOnly && !r.Open {
			continue
		}
		filtered = append(filtered, r)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(filtered)
}
