//go:build darwin

package processinfo

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"os"
)

func GetProcessInfo(pid int) (Info, error) {
	info := Info{PID: pid}

	out, err := exec.Command("/bin/sh", "-c", fmt.Sprintf("ps -p %d -o comm=,uid=", pid)).Output()
	if err != nil {
		return info, fmt.Errorf("ps query failed: %w", err)
	}

	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) >= 1 {
		info.Name = fields[0]
	}
	if len(fields) >= 2 {
		if uid, err := strconv.Atoi(fields[1]); err == nil {
			info.Username = uidToUsername(uid)
			setPrivileges(&info, uid)
		}
	}

	if info.Name != "" {
		out, _ := exec.Command("/usr/bin/which", info.Name).CombinedOutput()
		info.ExePath = strings.TrimSpace(string(out))
		if info.ExePath == "" {
			info.ExePath = filepath.Join("/usr/bin/", info.Name)
		}
	}

	return info, nil
}

func setPrivileges(info *Info, uid int) {
	if uid == 0 {
		info.PrivLevel = SYSTEM
		info.IsSystem = true
		info.Integrity = System
		info.TokenElev = Full
	} else if uid > 0 && uid <= 999 {
		info.PrivLevel = Elevated
		info.Integrity = High
		info.TokenElev = Default
	} else {
		info.PrivLevel = Standard
		info.Integrity = Medium
		info.TokenElev = Default
	}

	info.IsSigned = false
	if info.ExePath != "" {
		info.Signer = "N/A"
	}
}

func uidToUsername(uid int) string {
	passwd, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return fmt.Sprintf("uid%d", uid)
	}
	for _, line := range strings.Split(string(passwd), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 3 {
			if v, err := strconv.Atoi(fields[2]); err == nil && v == uid {
				return fields[0]
			}
		}
	}
	return fmt.Sprintf("uid%d", uid)
}

func IsProcessElevated(info Info) bool {
	return info.PrivLevel == SYSTEM || info.PrivLevel == Elevated
}

func IsProcessUnsigned(info Info) bool {
	return info.ExePath != "" && !info.IsSigned
}

func IsSuspiciousPath(exePath string) bool {
	lower := strings.ToLower(exePath)
	return strings.Contains(lower, "/private/tmp/") ||
		strings.Contains(lower, "/tmp/") ||
		strings.Contains(lower, "/var/folders/")
}
