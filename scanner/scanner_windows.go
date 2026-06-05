//go:build windows

package scanner

import (
	"fmt"
	"os/exec"
	"strings"
)

func enumerateProcesses() ([]ProcessEntry, error) {
	out, err := exec.Command("wmic", "process", "get", "Name,ProcessId", "/format:list").Output()
	if err != nil {
		return nil, fmt.Errorf("wmic process failed: %w", err)
	}

	// wmic /format:list format:
	//   Name=xxx\n\nProcessId=1234\n\n\n\nName=yyy\n\nProcessId=5678
	// Within an entry: Name and ProcessId separated by 1 blank line
	// Between entries: multiple blank lines
	// Strategy: emit as soon as both Name and ProcessId are present
	lines := strings.Split(string(out), "\n")
	var procs []ProcessEntry
	var hasName bool
	var current ProcessEntry
	for _, line := range lines {
		if strings.HasPrefix(line, "Name=") {
			current.Name = strings.TrimSpace(strings.TrimPrefix(line, "Name="))
			hasName = true
		} else if strings.HasPrefix(line, "ProcessId=") {
			var pid int
			fmt.Sscanf(strings.TrimSpace(strings.TrimPrefix(line, "ProcessId=")), "%d", &pid)
			current.PID = pid
			if hasName && current.PID >= 0 {
				procs = append(procs, current)
				current = ProcessEntry{}
				hasName = false
			}
		}
	}
	return procs, nil
}

func getNetConnections(connSet map[int]*Connection) ([]Connection, error) {
	out, err := exec.Command("netstat", "-ano").Output()
	if err != nil {
		return nil, fmt.Errorf("netstat failed: %w", err)
	}

	var conns []Connection
	lines := strings.Split(string(out), "\n")
	inTable := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "Active Connections") {
			inTable = true
			continue
		}
		if !inTable {
			continue
		}

		// Skip header/separator lines
		if strings.Contains(line, "-----") || line == "" || line == "Proto" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 5 {
			continue
		}

		proto := strings.ToUpper(parts[0])
		if proto != "TCP" && proto != "TCPV6" && proto != "UDP" && proto != "UDPV6" {
			continue
		}

		localAddr := parseWindowsAddr(parts[1])
		remoteAddr := parseWindowsAddr(parts[2])
		state := parts[3]
		pidStr := parts[4]

		var pid int
		fmt.Sscanf(pidStr, "%d", &pid)
		if pid < 0 {
			continue
		}

		c := Connection{
			ProcessID:  pid,
			LocalAddr:  localAddr.ip,
			LocalPort:  localAddr.port,
			RemoteAddr: remoteAddr.ip,
			RemotePort: remoteAddr.port,
			Protocol:   proto,
			State:      state,
		}

		if connSet != nil {
			connSet[pid] = &c
		}
		conns = append(conns, c)
	}

	return conns, nil
}

type winAddr struct {
	ip   string
	port int
}

func parseWindowsAddr(s string) winAddr {
	if s == "*" {
		return winAddr{ip: "*", port: 0}
	}

	clean := s

	lastColon := strings.LastIndex(clean, ":")
	if lastColon == -1 {
		return winAddr{ip: clean, port: 0}
	}

	var port int
	fmt.Sscanf(clean[lastColon+1:], "%d", &port)

	return winAddr{ip: clean[:lastColon], port: port}
}

func suspiciousProcsForOS() map[string]struct{} {
	return map[string]struct{}{
		"cmd.exe": {}, "powershell.exe": {}, "wscript.exe": {}, "cscript.exe": {},
		"wmic.exe": {}, "certutil.exe": {}, "bitsadmin.exe": {}, "dns.exe": {},
		"net.exe": {}, "ssh.exe": {}, "curl.exe": {}, "netsh.exe": {},
		"sc.exe": {}, "whoami.exe": {}, "mshta.exe": {}, "regsvr32.exe": {},
		"msbuild.exe": {}, "tasklist.exe": {}, "ipconfig.exe": {},
	}
}
