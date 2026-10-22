package sdk

import (
	"errors"
	"net"
	"os"
	"strconv"
)

const (
	// NativeMCPLocalPortEnv may be set independently for each Go MCP process.
	// It changes only the listener port; all listeners remain on IPv4 loopback.
	NativeMCPLocalPortEnv = "OSOP_NATIVE_MCP_LOCAL_PORT"
	minNativeMCPLocalPort = 1024
)

var errNativeMCPLocalPort = errors.New("native MCP local port must be a decimal integer from 1024 through 65535")

// LocalPortAddress returns a bounded loopback-only bind address for a native
// Go MCP service. An absent override retains the service's original port.
// Present but invalid overrides fail startup; no alternative port is chosen.
func LocalPortAddress(defaultPort uint16) (string, error) {
	if defaultPort < minNativeMCPLocalPort {
		return "", errNativeMCPLocalPort
	}

	port := int(defaultPort)
	if raw, present := os.LookupEnv(NativeMCPLocalPortEnv); present {
		// Accept only the canonical ASCII decimal spelling. This excludes
		// signs, whitespace, leading zeros, IPv4/IPv6 bind hints and suffixes.
		if len(raw) < 4 || len(raw) > 5 || raw[0] == '0' {
			return "", errNativeMCPLocalPort
		}
		for i := 0; i < len(raw); i++ {
			if raw[i] < '0' || raw[i] > '9' {
				return "", errNativeMCPLocalPort
			}
		}
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < minNativeMCPLocalPort || parsed > 65535 {
			return "", errNativeMCPLocalPort
		}
		port = parsed
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), nil
}
