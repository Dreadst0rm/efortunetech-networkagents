package systeminfo

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
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
	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("os.Hostname failed: %w", err)
	}
	if strings.TrimSpace(hostname) == "" {
		return "", fmt.Errorf("hostname is empty")
	}
	return hostname, nil
}

func getOSPlatform() string {
	return runtime.GOOS
}

// getLocalIPs retrieves all IP addresses bound to the local machine.
func getLocalIPs() ([]string, error) {
	var ips []string
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("net.Interfaces failed: %w", err)
	}

	for _, iface := range interfaces {
		// Skip down or loopback interfaces
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP != nil {
				// Only accept non-loopback addresses
				if !ipnet.IP.IsLoopback() {
					ips = append(ips, ipnet.IP.String())
				}
			}
		}
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found on any interface")
	}

	return ips, nil
}

// getMACAddresses attempts to get MAC addresses using platform commands.
func getMACAddresses() ([]string, error) {
	var output []byte
	var cmd *exec.Cmd

	macPattern := regexp.MustCompile(`([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}`)

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "ipconfig", "/all")
	case "linux":
		cmd = exec.Command("sh", "-c", "ip link show")
	case "darwin":
		cmd = exec.Command("networksetup", "-listallhardwareports")
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run command: %w", err)
	}

	var macs []string
	seen := make(map[string]bool)

	for _, line := range strings.Split(string(output), "\n") {
		mac := macPattern.FindString(line)
		if mac == "" {
			continue
		}

		mac = strings.ToUpper(mac)
		mac = strings.Replace(mac, "-", ":", -1)

		if seen[mac] {
			continue
		}

		if mac == "00:00:00:00:00:00" {
			continue
		}

		seen[mac] = true
		macs = append(macs, mac)
	}

	if len(macs) == 0 {
		return nil, fmt.Errorf("no MAC addresses found")
	}

	return macs, nil
}
