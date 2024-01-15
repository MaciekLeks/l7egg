package core

import "fmt"

// staty is a compound key that represents FQDN, IP, protocol, and port for metrics purposes.
// It is used for identifying and organizing assets in the Eggy struct.
type staty struct {
	fqdn string
	ip   string
}

func (f staty) String() string {
	return fmt.Sprintf("fqdn:%s;ip:%s", f.fqdn, f.ip)
}
