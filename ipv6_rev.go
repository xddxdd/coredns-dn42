package dn42

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

const IPv6_PTR_SUFFIX = ".ip6.arpa."

func (dn42 DN42) parseIPv6Query(ip string) (string, int) {
	splitted := strings.Split(ip, ".")
	reverse(splitted)
	ipMaskMax := 4 * len(splitted)
	for len(splitted) < 32 {
		splitted = append(splitted, "0")
	}

	result := ""
	for i := 0; i < 32; i++ {
		if i != 0 && i%4 == 0 {
			result += ":"
		}
		result += splitted[i]
	}
	return result, ipMaskMax
}

func (dn42 DN42) parseIPv6Ptr(qname string) (*net.IP, int, error) {
	if !strings.HasSuffix(qname, IPv6_PTR_SUFFIX) {
		return nil, 0, errors.New("not IPv6 ptr query")
	}

	qname = strings.TrimSuffix(qname, IPv6_PTR_SUFFIX)
	ipString, ipMask := dn42.parseIPv6Query(qname)

	ip := net.ParseIP(ipString)
	if ip == nil {
		return nil, 0, errors.New("not IPv6 ptr query")
	}
	if ip.To4() != nil {
		return nil, 0, errors.New("not IPv6 ptr query")
	}
	return &ip, ipMask, nil
}

func (dn42 DN42) findIPv6RecordFile(ip net.IP, ipMask int) (string, int, error) {
	ipString := ip.String()
	for i := ipMask; i >= 0; i-- {
		_, cidr, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ipString, i))
		if err != nil {
			return "", 0, err
		}

		cidrFilename := strings.ReplaceAll(cidr.String(), "/", "_")
		if dn42.fileExists("inet6num", cidrFilename) {
			return cidrFilename, i, nil
		}
	}

	return "", 0, errors.New("file for range not found")
}
