package utils

import (
	"fmt"
	"os"
	"strings"
)

func CleanHostame(hostname string) (string, error) {
	hostname = strings.TrimSpace(hostname)
	if len(hostname) == 0 {
		return "", fmt.Errorf("empty hostname is invalid")
	}

	return strings.ToLower(hostname), nil
}

// GetHostname returns OS's hostname.
func GetHostname() (string, error) {
	// hostname is read from file /proc/sys/kernel/hostname
	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("could not determine hostname: %w", err)
	}

	return CleanHostame(hostname)
}
