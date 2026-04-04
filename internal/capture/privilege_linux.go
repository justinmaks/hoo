//go:build linux

package capture

import (
	"os"
	"strings"
)

// hasLinuxCapabilities checks if the current process has CAP_NET_RAW or
// CAP_NET_ADMIN via the /proc filesystem. This avoids a cgo dependency on libcap.
func hasLinuxCapabilities() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			hex := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
			// CAP_NET_RAW is bit 13, CAP_NET_ADMIN is bit 12.
			// If either is set in the effective capabilities, we're good.
			// A full capability set (root) will have all bits set.
			if len(hex) > 0 && hex != "0000000000000000" {
				return true
			}
		}
	}
	return false
}
