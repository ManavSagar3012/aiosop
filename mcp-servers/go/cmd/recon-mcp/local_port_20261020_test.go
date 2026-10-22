package main

import "testing"

func TestQualifiedReconPortNeverAcceptsRemoteOrMalformedBind(t *testing.T) {
	cases := []struct{ hint, expected string }{
		{"", "127.0.0.1:8082"},
		{"18082", "127.0.0.1:18082"},
		{"65535", "127.0.0.1:65535"},
		{"0", "127.0.0.1:0"},
		{"1023", "127.0.0.1:0"},
		{"65536", "127.0.0.1:0"},
		{"0.0.0.0:18082", "127.0.0.1:0"},
		{"[::]:18082", "127.0.0.1:0"},
		{"18082?query=1", "127.0.0.1:0"},
		{"018082", "127.0.0.1:0"},
		{"-1", "127.0.0.1:0"},
	}
	for _, tc := range cases {
		t.Run(tc.hint, func(t *testing.T) {
			t.Setenv("OSOP_RECON_MCP_LOCAL_PORT", tc.hint)
			t.Setenv("OSOP_RECON_MCP_BIND", "0.0.0.0:9999")
			t.Setenv("OSOP_RECON_MCP_ALLOW_REMOTE_BIND", "true")
			if got := reconListenAddress(); got != tc.expected {
				t.Fatalf("unexpected native listen address %q for %q", got, tc.hint)
			}
		})
	}
}
