package scanner

import (
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// Result is the outcome of probing a single host:port.
type Result struct {
	Host      string
	Port      int
	Open      bool
	Banner    string
	TLSExpiry *TLSInfo
	Err       error
}

// TLSInfo summarizes the leaf certificate seen on a TLS connection.
type TLSInfo struct {
	Issuer         string
	NotAfter       time.Time
	DaysRemaining  int
	Expired        bool
}

// Options configures a scan run.
type Options struct {
	Concurrency int
	Timeout     time.Duration
	GrabBanner  bool
	CheckTLS    bool
}

// DefaultOptions returns sane defaults for a scan: 100 workers, a 2 second
// per-connection timeout, with banner grabbing and TLS checks enabled.
func DefaultOptions() Options {
	return Options{
		Concurrency: 100,
		Timeout:     2 * time.Second,
		GrabBanner:  true,
		CheckTLS:    true,
	}
}

// Scan probes every host x port combination concurrently using a worker
// pool bounded by opts.Concurrency, and returns results sorted by
// host then port.
func Scan(hosts []string, ports []int, opts Options) []Result {
	type job struct {
		host string
		port int
	}

	jobs := make(chan job)
	resultsCh := make(chan Result)
	var wg sync.WaitGroup

	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				resultsCh <- probe(j.host, j.port, opts)
			}
		}()
	}

	go func() {
		for _, h := range hosts {
			for _, p := range ports {
				jobs <- job{host: h, port: p}
			}
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	var results []Result
	for r := range resultsCh {
		results = append(results, r)
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Host != results[j].Host {
			return results[i].Host < results[j].Host
		}
		return results[i].Port < results[j].Port
	})
	return results
}

func probe(host string, port int, opts Options) Result {
	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", address, opts.Timeout)
	if err != nil {
		return Result{Host: host, Port: port, Open: false}
	}
	defer conn.Close()

	result := Result{Host: host, Port: port, Open: true}

	if opts.CheckTLS && port == 443 {
		result.TLSExpiry = probeTLS(host, port, opts.Timeout)
	}

	if opts.GrabBanner {
		result.Banner = grabBanner(conn, opts.Timeout)
	}

	return result
}

func grabBanner(conn net.Conn, timeout time.Duration) string {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}
	return sanitizeBanner(string(buf[:n]))
}

func sanitizeBanner(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '\n' || r == '\r' {
			break
		}
		if r >= 32 && r < 127 {
			out = append(out, r)
		}
	}
	return string(out)
}

func probeTLS(host string, port int, timeout time.Duration) *TLSInfo {
	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // we're only reading the cert, not validating trust
	})
	if err != nil {
		return nil
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}
	leaf := certs[0]
	remaining := int(time.Until(leaf.NotAfter).Hours() / 24)
	return &TLSInfo{
		Issuer:        leaf.Issuer.CommonName,
		NotAfter:      leaf.NotAfter,
		DaysRemaining: remaining,
		Expired:       remaining < 0,
	}
}
