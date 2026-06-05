//go:build linux

package processinfo

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func GetProcessInfo(pid int) (Info, error) {
	info := Info{PID: pid}

	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err == nil && exePath != "" {
		info.ExePath = exePath
		info.Name = filepath.Base(exePath)
	}

	statusData, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return info, fmt.Errorf("read /proc/%d/status: %w", pid, err)
	}

	var uid, euid int
	for _, line := range strings.Split(string(statusData), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "Uid:" {
			if v, err := strconv.Atoi(fields[1]); err == nil {
				uid = v
			}
			if v, err := strconv.Atoi(fields[2]); err == nil {
				euid = v
			}
		}
	}

	info.Username = uidToUsername(uid)
	setPrivileges(&info, euid)
	return info, nil
}

func setPrivileges(info *Info, euid int) {
	if euid == 0 {
		info.PrivLevel = SYSTEM
		info.IsSystem = true
		info.Integrity = System
		info.TokenElev = Full
	} else if euid > 0 && euid <= 999 {
		info.PrivLevel = Elevated
		info.Integrity = High
		info.TokenElev = Full
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

func init() {
	suspiciousPathPatterns = append(suspiciousPathPatterns,
		"/tmp/",
		"/var/tmp/",
	)
}
