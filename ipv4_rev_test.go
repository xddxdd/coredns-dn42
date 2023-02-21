package dn42

import (
	"fmt"
	"net"
	"testing"

	"github.com/coredns/coredns/plugin/test"
)

func testIPv4CNAMERecord(t *testing.T, ipString string, mask int, expected string) {
	x := DN42{
		DN42RegistryPath: "/",
		Ttl:              3600,
		Next:             test.ErrorHandler(),
	}

	ip := net.ParseIP(ipString)
	_, newQname, _ := x.generateIPv4CNAMERecord("", ip, mask)
	if newQname != expected {
		t.Errorf("newQname (%s) != expected (%s)", newQname, expected)
	}
}

func TestIPv4CNAMERecord(t *testing.T) {
	for i := 0; i <= 32; i++ {
		testIPv4CNAMERecord(t, "192.168.0.1", i, fmt.Sprintf("1/%d.0.168.192.in-addr.arpa.", i))
	}
}
