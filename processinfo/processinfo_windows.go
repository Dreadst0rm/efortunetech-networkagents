//go:build windows

package processinfo

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

func GetProcessInfo(pid int) (Info, error) {
	script := fmt.Sprintf(
		"$proc = Get-Process -Id %d -ErrorAction SilentlyContinue"+
			"\nif (-not $proc) { Write-Output 'ERR|no_process'; exit }"+
			"\n$name = $proc.ProcessName"+
			"\n$exePath = ''"+
			"\nif ($proc.MainModule) { try { $exePath = $proc.MainModule.FileName } catch { $exePath = '' } }"+
			"\n$username = 'unknown'"+
			"\n$isSystem = $false"+
			"\nif ($exePath -and (Test-Path $exePath)) { "+
			"\n  try { "+
			"\n    $o = Get-CimInstance Win32_Process -Filter \"ProcessId=%d\""+
			"\n    if ($o) { "+
			"\n      $username = \"${o.Name}\""+
			"\n      $isSystem = ($username -eq 'SYSTEM') "+
			"\n    }"+
			"\n  } catch { }"+
			"\n}"+
			"\n$priv = 'standard'"+
			"\nif ($isSystem) { $priv = 'system' }"+
			"\n$integrity = 'medium'"+
			"\n$signer = ''"+
			"\n$isSigned = $false"+
			"\nif ($exePath -ne '' -and (Test-Path $exePath)) { "+
			"\n  try { "+
			"\n    $sig = Get-AuthenticodeSignature -FilePath $exePath -ErrorAction SilentlyContinue"+
			"\n    if ($sig.SignatureStatus -eq 'Valid') { "+
			"\n      $isSigned = $true"+
			"\n      $signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { 'Signed' }"+
			"\n    }"+
			"\n  } catch { }"+
			"\n}"+
			"\n$tokenElev = 2"+
			"\nif ($priv -eq 'system' -or $integrity -eq 'high' -or $integrity -eq 'system') { $tokenElev = 1 }"+
			"\nWrite-Output \"${pid}\t${name}\t${username}\t${priv}\t${exePath}\t${isSystem}\t${integrity}\t${signer}\t${isSigned}\t${tokenElev}\"",
		pid, pid)

	cmd := exec.Command("powershell.exe", "-Command", script)
	output, err := cmd.Output()
	if err != nil {
		return Info{}, fmt.Errorf("powershell query failed: %w", err)
	}

	line := strings.TrimSpace(string(output))
	if strings.HasPrefix(line, "ERR|") {
		return Info{}, fmt.Errorf("%s", line[4:])
	}

	return parsePrivOutput(pid, line), nil
}

func parsePrivOutput(pid int, line string) Info {
	var info Info
	info.PID = pid
	parts := strings.Split(line, "\t")
	if len(parts) < 10 {
		return info
	}
	info.Name = parts[1]
	info.Username = parts[2]
	switch parts[3] {
	case "system":
		info.PrivLevel = SYSTEM
	case "elevated":
		info.PrivLevel = Elevated
	default:
		info.PrivLevel = Standard
	}
	info.ExePath = parts[4]
	if strings.ToLower(parts[5]) == "true" {
		info.IsSystem = true
	}
	switch parts[6] {
	case "system":
		info.Integrity = System
	case "high":
		info.Integrity = High
	case "medium":
		info.Integrity = Medium
	case "low":
		info.Integrity = Low
	}
	if len(parts) >= 8 {
		info.Signer = parts[7]
	}
	if strings.ToLower(parts[8]) == "true" {
		info.IsSigned = true
	}
	switch val, _ := strconv.Atoi(parts[9]); val {
	case 1:
		info.TokenElev = Full
	case 2:
		info.TokenElev = Limited
	default:
		info.TokenElev = Default
	}
	return info
}

func IsProcessElevated(info Info) bool {
	return info.PrivLevel == Elevated || info.PrivLevel == SYSTEM
}

func IsProcessUnsigned(info Info) bool {
	return info.ExePath != "" && !info.IsSigned
}

func init() {
	suspiciousPathPatterns = append(suspiciousPathPatterns,
		"appdata\\local\\temp",
		"\\tmp\\",
		"users\\public\\",
	)
}
