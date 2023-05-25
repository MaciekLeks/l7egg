package tools

import (
	"fmt"
	"os"
	"strings"
)

// GetHostname returns OS's hostname.
func GetHostname() (string, error) {
	hostName, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("could not determine hostname: %w", err)
	}

	// hostname is read from file /proc/sys/kernel/hostname
	hostName = strings.TrimSpace(hostName)
	if len(hostName) == 0 {
		return "", fmt.Errorf("empty hostname is invalid")
	}

	return strings.ToLower(hostName), nil
}
