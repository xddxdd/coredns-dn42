package dn42

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

const IPv6_PTR_SUFFIX = ".ip6.arpa."

func (dn42 DN42) parseIPv6Query(ip string) (string, error) {
	splitted := strings.Split(ip, ".")
	if len(splitted) != 32 {
		return "", errors.New("not IPv6 ptr query")
	}

	for i := 0; i < 16; i++ {
		splitted[i], splitted[31-i] = splitted[31-i], splitted[i]
	}

	result := ""
	for i := 0; i < 32; i++ {
		if i != 0 && i % 4 == 0 {
			result += ":"
		}
		result += splitted[i]
	}
	return result, nil
}

func (dn42 DN42) parseIPv6Ptr(qname string) (*net.IP, error) {
	if !strings.HasSuffix(qname, IPv6_PTR_SUFFIX) {
		return nil, errors.New("not IPv6 ptr query")
	}

	qname = strings.TrimSuffix(qname, IPv6_PTR_SUFFIX)
	ipString, err := dn42.parseIPv6Query(qname)
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(ipString)
	if ip == nil {
		return nil, errors.New("not IPv6 ptr query")
	}
	if ip.To4() != nil {
		return nil, errors.New("not IPv6 ptr query")
	}
	return &ip, nil
}

func (dn42 DN42) findIPv6RecordFile(ip net.IP) (string, *net.IPNet, error) {
	ipString := ip.String()
	for i := 128; i >= 0; i-- {
		_, cidr, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ipString, i))
		if err != nil {
			return "", nil, err
		}

		cidrFilename := strings.ReplaceAll(cidr.String(), "/", "_")
		if dn42.fileExists("inet6num", cidrFilename) {
			return cidrFilename, cidr, nil
		}
	}

	return "", nil, errors.New("file for range not found")
}
