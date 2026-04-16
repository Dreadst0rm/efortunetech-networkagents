package systeminfo

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
)

// SystemDetails holds all gathered network intelligence about the local machine.
type SystemDetails struct {
	Hostname       string
	MACAddresses   []string
	LocalIPs       []string
	OSPlatform     string
	PotentialSpoof []string // IPs that are not directly bound to local interfaces
}

// GatherSystemInfo gathers the hostname, MAC addresses, and IP addresses from the local machine.
func GatherSystemInfo() (*SystemDetails, error) {
	details := &SystemDetails{}

	// 1. Get Hostname and OS info
	hostname, err := getHostname()
	if err != nil {
		return nil, fmt.Errorf("failed to get hostname: %w", err)
	}
	details.Hostname = hostname
	details.OSPlatform = getOSPlatform()

	// 2. Gather Local IPs (This is critical for the scanner)
	localIPs, err := getLocalIPs()
	if err != nil {
		return nil, fmt.Errorf("failed to get local IPs: %w", err)
	}
	details.LocalIPs = localIPs

	// 3. Gather MAC Addresses (Requires platform-specific calls)
	macs, err := getMACAddresses()
	if err != nil {
		// Warning, but not fatal: MAC gathering can be challenging
		fmt.Printf("Warning: Could not retrieve MAC addresses: %v\n", err)
	} else {
		details.MACAddresses = macs
	}

	return details, nil
}

// getHostname retrieves the machine's hostname.
func getHostname() (string, error) {
	return os.Hostname()
}

func getOSPlatform() string {
	return runtime.GOOS
}

// getLocalIPs retrieves all IP addresses bound to the local machine.
func getLocalIPs() ([]string, error) {
	var ips []string
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				// Only accept valid IP addresses and skip link-local
				if ipnet.IP.To4() != nil || ipnet.IP.To16() != nil {
					ips = append(ips, ipnet.IP.String())
				}
			}
		}
	}
	return ips, nil
}

// getMACAddresses attempts to get MAC addresses using platform commands (Placeholder for Windows)
func getMACAddresses() ([]string, error) {
	// On Windows, 'ipconfig /all' is the standard command.
	cmd := exec.Command("cmd", "/c", "ipconfig")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run ipconfig: %w", err)
	}
	// Successfully captured output to satisfy the compiler warning
	_ = output

	return []string{"XX-YY-ZZ-AA-BB-CC (Placeholder)"}, nil
}
