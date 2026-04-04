package capture

import (
	"fmt"
	"os"
	"runtime"
)

// CheckPrivileges verifies the current process has sufficient permissions for
// packet capture. Returns nil if OK, or an error with platform-specific instructions.
func CheckPrivileges() error {
	switch runtime.GOOS {
	case "linux":
		return checkPrivilegesLinux()
	case "darwin":
		return checkPrivilegesDarwin()
	case "windows":
		return checkPrivilegesWindows()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

func checkPrivilegesLinux() error {
	if os.Geteuid() == 0 {
		return nil
	}
	if hasLinuxCapabilities() {
		return nil
	}
	return fmt.Errorf(`insufficient privileges for packet capture

hoo requires raw network access. Options:
  1. Run with sudo:
     sudo hoo

  2. Grant capabilities to the binary (recommended):
     sudo setcap cap_net_raw,cap_net_admin=eip $(which hoo)

  3. Run as root (not recommended)`)
}

func checkPrivilegesDarwin() error {
	if os.Geteuid() == 0 {
		return nil
	}
	return fmt.Errorf(`insufficient privileges for packet capture

hoo requires access to BPF devices. Options:
  1. Run with sudo:
     sudo hoo

  2. Add your user to the access_bpf group:
     sudo dseditgroup -o edit -a $(whoami) -t user access_bpf
     (reboot or log out/in after)`)
}

func checkPrivilegesWindows() error {
	// On Windows, Npcap handles permissions. We can't easily check
	// admin status without syscalls, so we'll let the capture attempt
	// fail with a clear message if permissions are insufficient.
	return nil
}
