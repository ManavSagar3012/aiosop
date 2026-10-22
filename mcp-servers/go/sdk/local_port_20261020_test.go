package sdk

import (
	"os"
	"strings"
	"testing"
)

func TestLocalPortAddressUsesEachNativeServiceDefaultWhenUnset(t *testing.T) {
	previous, exists := os.LookupEnv(NativeMCPLocalPortEnv)
	if err := os.Unsetenv(NativeMCPLocalPortEnv); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if exists {
			_ = os.Setenv(NativeMCPLocalPortEnv, previous)
		} else {
			_ = os.Unsetenv(NativeMCPLocalPortEnv)
		}
	})

	for _, tc := range []struct {
		defaultPort uint16
		want        string
	}{
		{8083, "127.0.0.1:8083"},
		{8084, "127.0.0.1:8084"},
		{8085, "127.0.0.1:8085"},
		{8086, "127.0.0.1:8086"},
		{8087, "127.0.0.1:8087"},
	} {
		got, err := LocalPortAddress(tc.defaultPort)
		if err != nil || got != tc.want {
			t.Fatalf("default %d: got %q, err %v", tc.defaultPort, got, err)
		}
	}
}

func TestLocalPortAddressOverrideIsCanonicalAndLoopbackOnly(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"1024", "127.0.0.1:1024"},
		{"18083", "127.0.0.1:18083"},
		{"65535", "127.0.0.1:65535"},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			t.Setenv(NativeMCPLocalPortEnv, tc.raw)
			got, err := LocalPortAddress(8083)
			if err != nil || got != tc.want {
				t.Fatalf("override %q: got %q, err %v", tc.raw, got, err)
			}
			if safe, err := localAddress(got); err != nil || safe != got {
				t.Fatalf("SDK listener rejected safe override %q: %v", got, err)
			}
		})
	}
}

func TestLocalPortAddressInvalidOverrideCannotFallBackOrEscapeLoopback(t *testing.T) {
	for _, raw := range []string{
		"", "0", "1", "1023", "65536", "99999", "-1", "+18083", "018083",
		" 18083", "18083 ", "18083\n", "18083?foo", "18083/tcp", "18083.0",
		"0x46a3", "127.0.0.1:18083", "0.0.0.0:18083", "[::]:18083",
		"ｅ18083", strings.Repeat("9", 100),
	} {
		t.Run("invalid="+raw, func(t *testing.T) {
			t.Setenv(NativeMCPLocalPortEnv, raw)
			if address, err := LocalPortAddress(8084); err == nil || address != "" {
				t.Fatalf("unsafe override %q accepted as %q (%v)", raw, address, err)
			}
		})
	}

	t.Setenv(NativeMCPLocalPortEnv, "18083")
	if address, err := LocalPortAddress(0); err == nil || address != "" {
		t.Fatalf("invalid service default unexpectedly accepted: %q (%v)", address, err)
	}
}
