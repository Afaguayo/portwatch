package scanner

import (
	"reflect"
	"testing"
)

func TestParseHostsPlainList(t *testing.T) {
	hosts, err := ParseHosts("10.0.0.1, 10.0.0.2 ,example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"10.0.0.1", "10.0.0.2", "example.com"}
	if !reflect.DeepEqual(hosts, want) {
		t.Errorf("got %v, want %v", hosts, want)
	}
}

func TestParseHostsExpandsCIDR(t *testing.T) {
	hosts, err := ParseHosts("192.168.1.0/30")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// /30 has 4 addresses; network and broadcast are dropped, leaving 2 usable hosts.
	want := []string{"192.168.1.1", "192.168.1.2"}
	if !reflect.DeepEqual(hosts, want) {
		t.Errorf("got %v, want %v", hosts, want)
	}
}

func TestParseHostsMixedListAndCIDR(t *testing.T) {
	hosts, err := ParseHosts("10.0.0.5,192.168.1.0/30")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"10.0.0.5", "192.168.1.1", "192.168.1.2"}
	if !reflect.DeepEqual(hosts, want) {
		t.Errorf("got %v, want %v", hosts, want)
	}
}

func TestParseHostsRejectsEmpty(t *testing.T) {
	if _, err := ParseHosts(""); err == nil {
		t.Error("expected error for empty host spec")
	}
}

func TestParseHostsRejectsBadCIDR(t *testing.T) {
	if _, err := ParseHosts("10.0.0.0/abc"); err == nil {
		t.Error("expected error for malformed CIDR")
	}
}

func TestParsePortsSingleAndList(t *testing.T) {
	ports, err := ParsePorts("22,80,443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []int{22, 80, 443}
	if !reflect.DeepEqual(ports, want) {
		t.Errorf("got %v, want %v", ports, want)
	}
}

func TestParsePortsRange(t *testing.T) {
	ports, err := ParsePorts("8000-8003")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []int{8000, 8001, 8002, 8003}
	if !reflect.DeepEqual(ports, want) {
		t.Errorf("got %v, want %v", ports, want)
	}
}

func TestParsePortsMixedAndDeduped(t *testing.T) {
	ports, err := ParsePorts("22,80-82,80")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []int{22, 80, 81, 82}
	if !reflect.DeepEqual(ports, want) {
		t.Errorf("got %v, want %v", ports, want)
	}
}

func TestParsePortsRejectsOutOfRange(t *testing.T) {
	if _, err := ParsePorts("70000"); err == nil {
		t.Error("expected error for out-of-range port")
	}
	if _, err := ParsePorts("0"); err == nil {
		t.Error("expected error for port 0")
	}
}

func TestParsePortsRejectsInvertedRange(t *testing.T) {
	if _, err := ParsePorts("100-50"); err == nil {
		t.Error("expected error for inverted range")
	}
}

func TestParsePortsRejectsGarbage(t *testing.T) {
	if _, err := ParsePorts("not-a-port"); err == nil {
		t.Error("expected error for non-numeric port")
	}
}
