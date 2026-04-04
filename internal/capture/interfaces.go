package capture

import (
	"fmt"
	"net"
	"strings"
)

// InterfaceInfo holds information about a network interface.
type InterfaceInfo struct {
	Name      string
	Addresses []string
	Up        bool
	Loopback  bool
}

// ListInterfaces returns information about all network interfaces.
func ListInterfaces() ([]InterfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("listing interfaces: %w", err)
	}

	var result []InterfaceInfo
	for _, iface := range ifaces {
		info := InterfaceInfo{
			Name:     iface.Name,
			Up:       iface.Flags&net.FlagUp != 0,
			Loopback: iface.Flags&net.FlagLoopback != 0,
		}

		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				info.Addresses = append(info.Addresses, addr.String())
			}
		}

		result = append(result, info)
	}

	return result, nil
}

// DetectDefaultInterface finds the best interface for capture.
// Prefers the first non-loopback interface with an active link and an address.
func DetectDefaultInterface() (string, error) {
	ifaces, err := ListInterfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range ifaces {
		if !iface.Loopback && iface.Up && len(iface.Addresses) > 0 {
			return iface.Name, nil
		}
	}

	return "", fmt.Errorf("no suitable network interface found\n\nAvailable interfaces:\n%s", formatInterfaceList(ifaces))
}

// FormatInterfaceTable returns a formatted table of interfaces for display.
func FormatInterfaceTable(ifaces []InterfaceInfo) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%-16s %-40s %-8s\n", "NAME", "ADDRESSES", "STATE")
	fmt.Fprintf(&b, "%-16s %-40s %-8s\n", "----", "---------", "-----")
	for _, iface := range ifaces {
		state := "down"
		if iface.Up {
			state = "up"
		}
		if iface.Loopback {
			state += " (lo)"
		}
		addrs := strings.Join(iface.Addresses, ", ")
		if addrs == "" {
			addrs = "-"
		}
		fmt.Fprintf(&b, "%-16s %-40s %-8s\n", iface.Name, addrs, state)
	}
	return b.String()
}

// InterfaceIPs returns the IP addresses for a given interface name.
func InterfaceIPs(name string) ([]net.IP, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", name, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("addresses for %s: %w", name, err)
	}

	var ips []net.IP
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip != nil {
			ips = append(ips, ip)
		}
	}

	return ips, nil
}

func formatInterfaceList(ifaces []InterfaceInfo) string {
	var b strings.Builder
	for _, iface := range ifaces {
		state := "down"
		if iface.Up {
			state = "up"
		}
		fmt.Fprintf(&b, "  %s (%s)\n", iface.Name, state)
	}
	return b.String()
}
