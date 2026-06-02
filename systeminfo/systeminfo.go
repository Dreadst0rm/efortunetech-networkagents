package systeminfo

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
)

type SystemDetails struct {
	Hostname     string
	OSPlatform   string
	LocalIPs     []string
	MACAddresses []string
}

func Gather() (*SystemDetails, error) {
	d := &SystemDetails{}

	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("hostname: %w", err)
	}
	if strings.TrimSpace(hostname) == "" {
		return nil, fmt.Errorf("hostname is empty")
	}
	d.Hostname = hostname
	d.OSPlatform = runtime.GOOS

	var localIPs []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("net.Interfaces: %w", err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP != nil && !ipnet.IP.IsLoopback() {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					localIPs = append(localIPs, ip4.String())
				}
			}
		}
	}
	if len(localIPs) > 0 {
		d.LocalIPs = localIPs
	}

	return d, nil
}
