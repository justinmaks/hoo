//go:build !linux

package capture

import (
	"context"
	"fmt"
)

// NewBackend creates the appropriate capture engine based on the backend name.
func NewBackend(backend, iface, filter string, output chan<- PacketData) CaptureEngine {
	if backend == "afpacket" {
		return &unsupportedBackend{name: "afpacket"}
	}
	return NewEngine(iface, filter, output)
}

type unsupportedBackend struct {
	name string
}

func (u *unsupportedBackend) Start(_ context.Context) error {
	return fmt.Errorf("backend %q is not supported on this platform", u.name)
}

func (u *unsupportedBackend) GetStats() Stats {
	return Stats{}
}
