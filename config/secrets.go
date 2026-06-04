package config

import "os"

// ResolveAPIKey tries to find an API key via a chain of sources, returning empty string if none found.
func ResolveAPIKey(envName string) string {
	if v := os.Getenv(envName); v != "" {
		return v
	}
	return ""
}
