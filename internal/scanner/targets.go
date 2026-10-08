// Package scanner implements target/port parsing and the concurrent TCP
// port scan + banner grab + TLS expiry check used by portwatch.
package scanner

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ParseHosts expands a comma-separated list of hosts and/or CIDR blocks
// into a flat list of individual host strings (IPs or hostnames).
//
// A plain hostname or IP is returned as-is. A CIDR block (e.g.
// "192.168.1.0/30") is expanded to every usable address in the block.
func ParseHosts(spec string) ([]string, error) {
	var hosts []string
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			expanded, err := expandCIDR(part)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", part, err)
			}
			hosts = append(hosts, expanded...)
		} else {
			hosts = append(hosts, part)
		}
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("no hosts found in %q", spec)
	}
	return hosts, nil
}

func expandCIDR(cidr string) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for current := cloneIP(ip.Mask(ipNet.Mask)); ipNet.Contains(current); incrementIP(current) {
		ips = append(ips, current.String())
	}

	// Drop network and broadcast addresses for IPv4 blocks larger than /31,
	// matching how most scanning tools treat a CIDR of hosts to probe.
	if len(ips) > 2 && isIPv4CIDR(ipNet) {
		ips = ips[1 : len(ips)-1]
	}
	return ips, nil
}

func isIPv4CIDR(ipNet *net.IPNet) bool {
	ones, bits := ipNet.Mask.Size()
	return bits == 32 && ones < 31
}

func cloneIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

// ParsePorts parses a comma-separated spec of ports and port ranges, e.g.
// "22,80,443,8000-8010", into a sorted, de-duplicated slice of ports.
func ParsePorts(spec string) ([]int, error) {
	seen := make(map[int]bool)
	var ports []int

	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			if len(bounds) != 2 {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
			start, err := parsePort(bounds[0])
			if err != nil {
				return nil, err
			}
			end, err := parsePort(bounds[1])
			if err != nil {
				return nil, err
			}
			if start > end {
				return nil, fmt.Errorf("invalid port range %q: start > end", part)
			}
			for p := start; p <= end; p++ {
				if !seen[p] {
					seen[p] = true
					ports = append(ports, p)
				}
			}
		} else {
			p, err := parsePort(part)
			if err != nil {
				return nil, err
			}
			if !seen[p] {
				seen[p] = true
				ports = append(ports, p)
			}
		}
	}

	if len(ports) == 0 {
		return nil, fmt.Errorf("no ports found in %q", spec)
	}
	return ports, nil
}

func parsePort(s string) (int, error) {
	p, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("invalid port %q: %w", s, err)
	}
	if p < 1 || p > 65535 {
		return 0, fmt.Errorf("port %d out of range (1-65535)", p)
	}
	return p, nil
}
