package scanner

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// ScanResult maps an IP address to a list of open ports and the associated services.
type ScanResult map[string]map[int]string

// RunScan performs concurrent, deep port scanning across the specified range.
func RunScan(cidr string, portStart, portEnd, maxHosts int) (ScanResult, error) {
	resultsMap := make(ScanResult)
	var wg sync.WaitGroup
	var mu sync.Mutex

	// 1. Parse the CIDR
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	// 2. Check if network is /17 or smaller (prefix >= 17)
	ones, _ := ipNet.Mask.Size()
	if ones < 17 {
		return nil, fmt.Errorf("network too large: subnet must be /17 or smaller (prefix must be >= 17, currently /%d)", ones)
	}

	// 3. Prepare target IP list
	var ips []string

	// Start from the network address
	baseIP := ipNet.IP.Mask(ipNet.Mask)

	// Use a temporary copy for iteration
	currentIP := make(net.IP, len(baseIP))
	copy(currentIP, baseIP)

	// Iterate and collect up to maxHosts
	for i := 0; i < maxHosts; i++ {
		ips = append(ips, currentIP.String())

		// Increment the IP address
		nextIP := make(net.IP, len(currentIP))
		copy(nextIP, currentIP)

		for j := len(nextIP) - 1; j >= 0; j-- {
			nextIP[j]++
			if nextIP[j] != 0 {
				break
			}
		}

		// Check if we reached the end of the subnet
		if !ipNet.Contains(nextIP) {
			break
		}

		// Update currentIP for next loop
		copy(currentIP, nextIP)
	}

	// 4. Semaphore to limit concurrency
	semChan := make(chan struct{}, 100)

	// 5. Start scanning
	for _, target := range ips {
		for p := portStart; p <= portEnd; p++ {
			wg.Add(1)
			go func(targetIP string, port int) {
				defer wg.Done()

				// Acquire semaphore
				semChan <- struct{}{}
				defer func() { <-semChan }()

				address := fmt.Sprintf("%s:%d", targetIP, port)
				conn, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
				if err == nil {
					conn.Close()
					service := fingerprintPort(port)

					mu.Lock()
					if _, ok := resultsMap[targetIP]; !ok {
						resultsMap[targetIP] = make(map[int]string)
					}
					resultsMap[targetIP][port] = service
					mu.Unlock()
				}
			}(target, p)
		}
	}

	wg.Wait()

	if len(resultsMap) == 0 {
		return nil, fmt.Errorf("no open ports found in the target range")
	}
	return resultsMap, nil
}

// fingerprintPort attempts to identify the running service name on a given port.
func fingerprintPort(port int) string {
	switch port {
	case 21:
		return "FTP"
	case 22:
		return "SSH"
	case 80:
		return "HTTP/Web Server"
	case 443:
		return "HTTPS/Web Server"
	case 3389:
		return "RDP/Remote Desktop"
	default:
		return "Open Port"
	}
}
