package dn42

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

const IPv4_PTR_SUFFIX = ".in-addr.arpa."

// Copied from go/src/net/ip.go
func simpleMaskLength(mask net.IPMask) int {
	var n int
	for i, v := range mask {
		if v == 0xff {
			n += 8
			continue
		}
		// found non-ff byte
		// count 1 bits
		for v&0x80 != 0 {
			n++
			v <<= 1
		}
		// rest must be 0 bits
		if v != 0 {
			return -1
		}
		for i++; i < len(mask); i++ {
			if mask[i] != 0 {
				return -1
			}
		}
		break
	}
	return n
}

func (dn42 DN42) maskLength(cidr net.IPNet) int {
	return simpleMaskLength(cidr.Mask)
}

func (dn42 DN42) reverseIPv4(ip string) (string, error) {
	splitted := strings.Split(ip, ".")
	if len(splitted) != 4 {
		return "", errors.New("not IPv4 ptr query")
	}

	splitted[0], splitted[1], splitted[2], splitted[3] = splitted[3], splitted[2], splitted[1], splitted[0]
	return strings.Join(splitted, "."), nil
}

func (dn42 DN42) parseIPv4Ptr(qname string) (*net.IP, error) {
	if !strings.HasSuffix(qname, IPv4_PTR_SUFFIX) {
		return nil, errors.New("not IPv4 ptr query")
	}

	qname = strings.TrimSuffix(qname, IPv4_PTR_SUFFIX)
	ipString, err := dn42.reverseIPv4(qname)
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(ipString)
	if ip == nil {
		return nil, errors.New("not IPv4 ptr query")
	}
	if ip.To4() == nil {
		return nil, errors.New("not IPv4 ptr query")
	}
	return &ip, nil
}

func (dn42 DN42) parseIPv4CIDRPtr(qname string) (*net.IPNet, error) {
	if !strings.HasSuffix(qname, IPv4_PTR_SUFFIX) {
		return nil, errors.New("not IPv4 ptr query")
	}

	qname = strings.TrimSuffix(qname, IPv4_PTR_SUFFIX)
	ipString, err := dn42.reverseIPv4(qname)
	if err != nil {
		return nil, err
	}

	_, cidr, err := net.ParseCIDR(ipString)
	if err != nil {
		return nil, err
	}
	if cidr == nil {
		return nil, errors.New("not IPv4 ptr query")
	}
	return cidr, nil
}

func (dn42 DN42) findIPv4CIDRRecordFile(cidr net.IPNet) (string, *net.IPNet, error) {
	ipString := cidr.IP.String()
	for i := simpleMaskLength(cidr.Mask); i >= 0; i-- {
		_, cidr, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ipString, i))
		if err != nil {
			return "", nil, err
		}

		cidrFilename := strings.ReplaceAll(cidr.String(), "/", "_")
		if dn42.fileExists("inetnum", cidrFilename) {
			return cidrFilename, cidr, nil
		}
	}

	return "", nil, errors.New("file for range not found")
}

func (dn42 DN42) findIPv4RecordFile(ip net.IP) (string, *net.IPNet, error) {
	cidr := net.IPNet{
		IP:   ip,
		Mask: net.IPv4Mask(255, 255, 255, 255),
	}
	return dn42.findIPv4CIDRRecordFile(cidr)
}

func (dn42 DN42) generateIPv4CNAMERecord(qname string, ip net.IP, cidr net.IPNet) ([]dns.RR, string, error) {
	ipCidrString := fmt.Sprintf("%s/%d", ip, dn42.maskLength(cidr))
	ipCidrString, err := dn42.reverseIPv4(ipCidrString)
	if err != nil {
		return []dns.RR{}, "", err
	}

	cnameRecord := &dns.CNAME{
		Hdr: dns.RR_Header{
			Name:   qname,
			Rrtype: dns.TypeCNAME,
			Class:  dns.ClassINET,
			Ttl:    dn42.Ttl,
		},
		Target: ipCidrString + IPv4_PTR_SUFFIX,
	}

	return []dns.RR{cnameRecord}, ipCidrString + IPv4_PTR_SUFFIX, nil
}
