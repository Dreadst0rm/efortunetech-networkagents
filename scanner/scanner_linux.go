//go:build linux

package scanner

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func enumerateProcesses() ([]ProcessInfo, error) {
	var procs []ProcessInfo

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pidStr := entry.Name()
		var pid int
		if _, err := fmt.Sscanf(pidStr, "%d", &pid); err != nil || pid <= 2 {
			continue
		}

		commPath := filepath.Join("/proc", pidStr, "comm")
		commBytes, err := os.ReadFile(commPath)
		if err != nil {
			continue
		}

		name := strings.TrimSpace(string(commBytes))
		if name == "" {
			continue
		}

		procs = append(procs, ProcessInfo{PID: pid, Name: name})
	}

	return procs, nil
}

func getNetConnections(connSet map[int]*Connection) ([]Connection, error) {
	// Build inode -> PID(s) map from /proc/[pid]/fd/* symlinks
	inodeToPIDs := make(map[string][]int)
	pidNames := make(map[int]string)

	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc: %w", err)
	}

	for _, entry := range procEntries {
		if !entry.IsDir() {
			continue
		}
		pidStr := entry.Name()
		var pid int
		if _, err := fmt.Sscanf(pidStr, "%d", &pid); err != nil || pid <= 2 {
			continue
		}

		commPath := filepath.Join("/proc", pidStr, "comm")
		if commBytes, err := os.ReadFile(commPath); err == nil {
			pidNames[pid] = strings.TrimSpace(string(commBytes))
		}

		fdDir := filepath.Join("/proc", pidStr, "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			inodeToPIDs[inode] = append(inodeToPIDs[inode], pid)
		}
	}

	var conns []Connection

	tcpConns, err := parseProcNetTCP("/proc/net/tcp", inodeToPIDs, "tcp")
	if err != nil {
		return nil, fmt.Errorf("parse /proc/net/tcp: %w", err)
	}
	conns = append(conns, tcpConns...)

	tcp6Conns, err := parseProcNetTCP("/proc/net/tcp6", inodeToPIDs, "tcp")
	if err != nil {
		return nil, fmt.Errorf("parse /proc/net/tcp6: %w", err)
	}
	conns = append(conns, tcp6Conns...)

	udpConns, err := parseProcNetUDP("/proc/net/udp", inodeToPIDs)
	if err != nil {
		return nil, fmt.Errorf("parse /proc/net/udp: %w", err)
	}
	conns = append(conns, udpConns...)

	udp6Conns, err := parseProcNetUDP("/proc/net/udp6", inodeToPIDs)
	if err != nil {
		return nil, fmt.Errorf("parse /proc/net/udp6: %w", err)
	}
	conns = append(conns, udp6Conns...)

	return conns, nil
}

func parseProcNetTCP(path string, inodeMap map[string][]int, proto string) ([]Connection, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil
	}

	var result []Connection
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")

	for i, line := range lines {
		if i == 0 {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		localAddr, err := hexToTCPAddr(fields[1])
		if err != nil {
			continue
		}
		remoteAddr, err := hexToTCPAddr(fields[2])
		if err != nil {
			continue
		}

		var state string
		switch fields[3] {
		case "01":
			state = "ESTABLISHED"
		case "02":
			state = "SYN_SENT"
		case "03":
			state = "SYN_RECV"
		case "04":
			state = "FIN_WAIT1"
		case "05":
			state = "FIN_WAIT2"
		case "06":
			state = "TIME_WAIT"
		case "07":
			state = "CLOSE"
		case "08":
			state = "CLOSE_WAIT"
		case "09":
			state = "LAST_ACK"
		case "0A":
			state = "LISTEN"
		case "0B":
			state = "CLOSING"
		default:
			state = fields[3]
		}

		conn := Connection{
			ProcessID:  -1,
			LocalAddr:  localAddr.IP.String(),
			LocalPort:  localAddr.Port,
			RemoteAddr: remoteAddr.IP.String(),
			RemotePort: remoteAddr.Port,
			Protocol:   proto,
			State:      state,
		}

		inode := fields[9]
		if inode != "0" {
			if pids := inodeMap[inode]; len(pids) > 0 {
				conn.ProcessID = pids[0]
			}
		}

		result = append(result, conn)
	}

	return result, nil
}

func parseProcNetUDP(path string, inodeMap map[string][]int) ([]Connection, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil
	}

	var result []Connection
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")

	for i, line := range lines {
		if i == 0 {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}

		localAddr, err := hexToTCPAddr(fields[1])
		if err != nil {
			continue
		}
		remoteAddr, err := hexToTCPAddr(fields[2])
		if err != nil {
			continue
		}

		conn := Connection{
			ProcessID:  -1,
			LocalAddr:  localAddr.IP.String(),
			LocalPort:  localAddr.Port,
			RemoteAddr: remoteAddr.IP.String(),
			RemotePort: remoteAddr.Port,
			Protocol:   "udp",
			State:      "UNCONN",
		}

		inode := fields[6]
		if inode != "0" {
			if pids := inodeMap[inode]; len(pids) > 0 {
				conn.ProcessID = pids[0]
			}
		}

		result = append(result, conn)
	}

	return result, nil
}

// hexToTCPAddr converts a hex "IP:port" string from /proc/net/* to *net.TCPAddr.
// In /proc/net/tcp (IPv4): addr bytes are already in network (big-endian) order.
// C0A80164 -> [0xC0, 0xA8, 0x01, 0x64] -> 192.168.1.100
// In /proc/net/tcp6 (IPv6): each hextet is 4 hex chars stored big-endian (2 bytes each).
func hexToTCPAddr(s string) (*net.TCPAddr, error) {
	colon := strings.LastIndex(s, ":")
	if colon == -1 {
		return nil, fmt.Errorf("invalid address %q", s)
	}

	port, err := strconv.Atoi(s[colon+1:])
	if err != nil {
		return nil, fmt.Errorf("invalid port in %q: %w", s, err)
	}

	ipHex := s[:colon]
	var ip net.IP

	// Detect IPv6: contains colons or is 32 hex chars
	if strings.Contains(ipHex, ":") || len(ipHex) == 32 {
		// /proc/net/tcp6 format: each hextet is XXXX (4 hex chars) = 16-bit value
		var parts [8]uint16
		for i := 0; i < 8; i++ {
			hexPart := ipHex[i*8 : (i+1)*8]
			val, err := strconv.ParseUint(hexPart, 16, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid IPv6 hextet %q: %w", hexPart, err)
			}
			parts[i] = uint16(val)
		}

		ipBytes := make([]byte, 16)
		for i := 0; i < 8; i++ {
			val := parts[i]
			ipBytes[i*2] = byte(val >> 8)
			ipBytes[i*2+1] = byte(val & 0xFF)
		}
		ip = net.IP(ipBytes)
		return &net.TCPAddr{IP: ip, Port: port}, nil
	}

	if len(ipHex) == 8 {
		// IPv4: each byte is 2 hex chars, bytes stored in network order
		vals := make([]byte, 4)
		for i := 0; i < 4; i++ {
			hexByte := ipHex[i*2 : (i+1)*2]
			v, err := strconv.ParseUint(hexByte, 16, 8)
			if err != nil {
				return nil, fmt.Errorf("invalid IPv4 byte %q: %w", hexByte, err)
			}
			vals[i] = byte(v)
		}
		ip = net.IP(vals)
	} else {
		return nil, fmt.Errorf("unrecognized address format %q", s)
	}

	return &net.TCPAddr{IP: ip, Port: port}, nil
}

func suspiciousProcsForOS() map[string]struct{} {
	return map[string]struct{}{
		"bash": {}, "sh": {}, "zsh": {}, "ksh": {}, "fish": {},
		"python": {}, "python3": {}, "perl": {}, "ruby": {},
		"nc": {}, "netcat": {}, "curl": {}, "wget": {},
		"ssh": {}, "scp": {}, "sftp": {}, "rsync": {},
		"sudo": {}, "su": {}, "passwd": {}, "crontab": {},
		"systemctl": {}, "iptables": {}, "ip": {}, "ifconfig": {},
		"netstat": {}, "ss": {}, "nmap": {}, "tcpdump": {},
		"awk": {}, "sed": {}, "grep": {}, "find": {},
		"base64": {}, "xxd": {}, "openssl": {},
	}
}
