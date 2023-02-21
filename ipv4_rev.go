package dn42

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

const IPv4_PTR_SUFFIX = ".in-addr.arpa."

func (dn42 DN42) reverseIPv4(ip string) (string, int) {
	splitted := strings.Split(ip, ".")
	reverse(splitted)
	ipMaskMax := 8 * len(splitted)
	for len(splitted) < 4 {
		splitted = append(splitted, "0")
	}
	return strings.Join(splitted, "."), ipMaskMax
}

func (dn42 DN42) parseIPv4Ptr(qname string) (*net.IP, int, error) {
	if !strings.HasSuffix(qname, IPv4_PTR_SUFFIX) {
		return nil, 0, errors.New("not IPv4 ptr query")
	}

	qname = strings.TrimSuffix(qname, IPv4_PTR_SUFFIX)
	ipString, ipMask := dn42.reverseIPv4(qname)

	splitted := strings.SplitN(ipString, "/", 2)
	if len(splitted) == 2 {
		ipString = splitted[0]
		queryMask, err := strconv.Atoi(splitted[1])
		if err != nil {
			return nil, 0, err
		}
		if ipMask > queryMask {
			ipMask = queryMask
		}
	}

	ip := net.ParseIP(ipString)
	if ip == nil {
		return nil, 0, errors.New("not IPv4 ptr query")
	}
	if ip.To4() == nil {
		return nil, 0, errors.New("not IPv4 ptr query")
	}
	return &ip, ipMask, nil
}

func (dn42 DN42) findIPv4RecordFile(ip net.IP, ipMask int) (string, int, error) {
	ipString := ip.String()
	for i := ipMask; i >= 0; i-- {
		_, cidr, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ipString, i))
		if err != nil {
			return "", 0, err
		}

		cidrFilename := strings.ReplaceAll(cidr.String(), "/", "_")
		if dn42.fileExists("inetnum", cidrFilename) {
			return cidrFilename, i, nil
		}
	}

	return "", 0, errors.New("file for range not found")
}

func (dn42 DN42) generateIPv4CNAMERecord(qname string, ip net.IP, ipMask int) ([]dns.RR, string, error) {
	ipCidrString := fmt.Sprintf("%s/%d", ip, ipMask)

	splitted := strings.Split(ipCidrString, ".")
	reverse(splitted)
	ipCidrString = strings.Join(splitted, ".")

	target := ipCidrString + IPv4_PTR_SUFFIX

	if target != qname {
		cnameRecord := &dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   qname,
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
				Ttl:    dn42.Ttl,
			},
			Target: target,
		}
		return []dns.RR{cnameRecord}, target, nil
	} else {
		return []dns.RR{}, target, nil
	}
}
