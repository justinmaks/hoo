//go:build linux

package capture

// NewBackend creates the appropriate capture engine based on the backend name.
func NewBackend(backend, iface, filter string, output chan<- PacketData) CaptureEngine {
	if backend == "afpacket" {
		return NewAFPacketEngine(iface, filter, output)
	}
	return NewEngine(iface, filter, output)
}
