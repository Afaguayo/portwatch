package scanner

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// startEchoServer starts a TCP listener on 127.0.0.1 that writes a fixed
// banner to every connection, and returns its port and a stop function.
func startEchoServer(t *testing.T, banner string) (port int, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test listener: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = conn.Write([]byte(banner))
			}()
		}
	}()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(portStr)
	return p, func() { _ = ln.Close() }
}

func TestScanDetectsOpenPortAndBanner(t *testing.T) {
	port, stop := startEchoServer(t, "SSH-2.0-OpenSSH_9.6\r\n")
	defer stop()

	results := Scan([]string{"127.0.0.1"}, []int{port}, Options{
		Concurrency: 4,
		Timeout:     500 * time.Millisecond,
		GrabBanner:  true,
		CheckTLS:    false,
	})

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if !r.Open {
		t.Error("expected port to be reported open")
	}
	if !strings.Contains(r.Banner, "OpenSSH") {
		t.Errorf("expected banner to contain OpenSSH, got %q", r.Banner)
	}
}

func TestScanReportsClosedPort(t *testing.T) {
	// Grab an ephemeral port, then close it immediately so nothing is listening.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate a port: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	_ = ln.Close()

	results := Scan([]string{"127.0.0.1"}, []int{port}, Options{
		Concurrency: 4,
		Timeout:     300 * time.Millisecond,
		GrabBanner:  false,
		CheckTLS:    false,
	})

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Open {
		t.Error("expected port to be reported closed")
	}
}

func TestScanCoversAllHostPortCombinations(t *testing.T) {
	port, stop := startEchoServer(t, "hi\r\n")
	defer stop()

	results := Scan([]string{"127.0.0.1", "127.0.0.1"}, []int{port, port + 1}, Options{
		Concurrency: 4,
		Timeout:     300 * time.Millisecond,
		GrabBanner:  false,
		CheckTLS:    false,
	})

	if len(results) != 4 {
		t.Fatalf("expected 4 results (2 hosts x 2 ports), got %d", len(results))
	}
}

func TestSanitizeBannerStripsControlCharsAndNewlines(t *testing.T) {
	got := sanitizeBanner("SSH-2.0-OpenSSH_9.6\r\nExtra line that should be dropped")
	want := "SSH-2.0-OpenSSH_9.6"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
