package bpf

import (
	"net"
	"testing"
)

func TestIPConversionRoundTrip(t *testing.T) {
	ip := net.ParseIP("1.2.3.4")
	v, err := ipToU32(ip)
	if err != nil {
		t.Fatalf("ipToU32 failed: %v", err)
	}

	out := u32ToIP(v)
	if got := out.String(); got != "1.2.3.4" {
		t.Fatalf("unexpected round-trip ip: %s", got)
	}
}

func TestRate(t *testing.T) {
	if got := rate(200, 100, 2.0); got != 50 {
		t.Fatalf("expected 50, got %d", got)
	}
	if got := rate(100, 200, 1.0); got != 0 {
		t.Fatalf("expected 0 for decreasing counter, got %d", got)
	}
	if got := rate(100, 100, 0); got != 0 {
		t.Fatalf("expected 0 for zero elapsed time, got %d", got)
	}
}
