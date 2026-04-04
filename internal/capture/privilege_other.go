//go:build !linux

package capture

func hasLinuxCapabilities() bool {
	return false
}
