//go:build darwin

package scanner

import (
	"fmt"
	"os/exec"
	"strings"
)

func enumerateProcesses() ([]ProcessInfo, error) {
	cmd := exec.Command("ps", "axco", "pid,comm")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("ps axco failed: %w", err)
	}

	var procs []ProcessInfo
	lines := strings.Split(string(output), "\n")

	for _, line := range lines[1:] { // skip header
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		var pid int
		fmt.Sscanf(parts[0], "%d", &pid)
		if pid <= 0 {
			continue
		}

		name := parts[1]
		if name == "" || len(name) >= 256 {
			continue
		}

		procs = append(procs, ProcessInfo{PID: pid, Name: name})
	}

	return procs, nil
}

func getNetConnections(connSet map[int]*Connection) ([]Connection, error) {
	cmd := exec.Command("lsof", "-nP", "-i")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("lsof -nP -i failed: %w", err)
	}

	var conns []Connection
	lines := strings.Split(string(output), "\n")

	for _, line := range lines[1:] { // skip header
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "COMMAND") {
			continue
		}

		conn := parseLsofLine(line)
		if conn != nil {
			conns = append(conns, *conn)
			if connSet != nil {
				connSet[conn.ProcessID] = conn
			}
		}
	}

	return conns, nil
}

func parseLsofLine(line string) *Connection {
	parts := strings.Fields(line)
	if len(parts) < 8 { // minimum: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME...
		return nil
	}

	var pid int
	fmt.Sscanf(parts[1], "%d", &pid)
	if pid <= 0 {
		return nil
	}

	name := parts[0]
	if name == "" || len(name) >= 256 {
		return nil
	}

	conn := &Connection{
		ProcessID: pid,
		Process:   name,
		Protocol:  "tcp", // default; UDP detected if TYPE column contains UDP
	}

	// Protocol detection from TYPE column area (index ~4)
	for _, f := range parts[4:] {
		up := strings.ToUpper(f)
		if up == "UDP" || len(up) > 3 && up[:3] == "UDP" {
			conn.Protocol = "udp"
			break
		}
	}

	// Scan right-to-left for the NAME column (usually last field(s)).
	// Parenthesized/bracketed text carries state like "(ESTABLISHED)", "[LISTEN]".
	for i := len(parts) - 1; i >= 4; i-- {
		field := parts[i]

		if (strings.HasPrefix(field, "(") && strings.HasSuffix(field, ")")) ||
			(strings.HasPrefix(field, "[") && strings.HasSuffix(field, "]")) {
			state := field[1 : len(field)-1]
			state = strings.ToUpper(strings.TrimSpace(state))
			if state != "" && conn.State == "" {
				conn.State = state
			}
			continue
		}

		// Name/Address columns always contain a colon (separating IP and port)
		if !strings.Contains(field, ":") {
			continue
		}

		parseLsofAddressField(field, conn)
		break // found the NAME column
	}

	return conn
}

func parseLsofAddressField(field string, c *Connection) {
	clean := strings.ReplaceAll(strings.ReplaceAll(field, "[", ""), "]", "")
	clean = strings.TrimSpace(clean)

	if clean == "" || clean == "*" || clean == "*:*" {
		c.LocalAddr = "0.0.0.0"
		c.RemoteAddr = "0.0.0.0"
		return
	}

	// Handle "->" arrow notation (TCP with remote address)
	if arrow := strings.Index(clean, "->"); arrow > 0 {
		localStr := clean[:arrow]
		remoteStr := clean[arrow+2:]

		c.LocalAddr, c.LocalPort = splitEndpoint(localStr)
		c.RemoteAddr, c.RemotePort = splitEndpoint(remoteStr)
		return
	}

	// Single endpoint (UDP or listening TCP). Parse as local address.
	addr, port := splitEndpoint(clean)
	c.LocalAddr = addr
	c.LocalPort = port

	// For UDP entries there is no real remote address from lsof
	if c.Protocol == "udp" {
		c.RemoteAddr = "*"
	} else {
		c.RemoteAddr = ""
		c.RemotePort = 0
	}
}

func splitEndpoint(s string) (addr string, port int) {
	last := strings.LastIndex(s, ":")
	if last < 1 || last >= len(s)-1 {
		return s, 0
	}

	addr = strings.TrimSpace(s[:last])
	fmt.Sscanf(strings.TrimSpace(s[last+1:]), "%d", &port)
	return addr, port
}

func suspiciousProcsForOS() map[string]struct{} {
	return map[string]struct{}{
		"/bin/sh":                {},
		"/bin/bash":              {},
		"/bin/zsh":               {},
		"/bin/fish":              {},
		"/usr/bin/python":        {},
		"/usr/local/bin/python3": {},
		"nc":                     {},
		"netcat":                 {},
		"curl":                   {},
		"wget":                   {},
		"ssh":                    {},
		"scp":                    {},
		"sftp":                   {},
		"rsync":                  {},
		"sudo":                   {},
		"su":                     {},
		"openssl":                {},
		"base64":                 {},
	}
}
