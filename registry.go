package dn42

import (
	"bufio"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

const NS_PREFIX = "nserver:            "
const DS_PREFIX = "ds-rdata:           "

func (dn42 DN42) createNSRecord(qname string, ns string) (*dns.NS, error) {
	return &dns.NS{
		Hdr: dns.RR_Header{
			Name:   qname,
			Rrtype: dns.TypeNS,
			Class:  dns.ClassINET,
			Ttl:    dn42.Ttl,
		},
		Ns: ns + ".",
	}, nil
}

func (dn42 DN42) createDSRecord(qname string, ds string) (*dns.DS, error) {
	splitted := strings.SplitN(ds, " ", 4)
	if len(splitted) != 4 {
		return nil, errors.New("incorrect number of fields in DS record")
	}

	keyTag, err := strconv.Atoi(splitted[0])
	if err != nil {
		return nil, err
	}

	algorithm, err := strconv.Atoi(splitted[1])
	if err != nil {
		return nil, err
	}

	digestType, err := strconv.Atoi(splitted[2])
	if err != nil {
		return nil, err
	}

	digest := strings.ReplaceAll(splitted[3], " ", "")

	return &dns.DS{
		Hdr: dns.RR_Header{
			Name:   qname,
			Rrtype: dns.TypeDS,
			Class:  dns.ClassINET,
			Ttl:    dn42.Ttl,
		},
		KeyTag:     uint16(keyTag),
		Algorithm:  uint8(algorithm),
		DigestType: uint8(digestType),
		Digest:     digest,
	}, nil
}

func (dn42 DN42) createARecordForNS(ns string, ip string) (*dns.A, error) {
	ipv4 := net.ParseIP(ip)
	if ipv4.To4() == nil {
		return nil, errors.New(ip + " is not a IPv4 address")
	}

	return &dns.A{
		Hdr: dns.RR_Header{
			Name:   ns + ".",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    dn42.Ttl,
		},
		A: ipv4,
	}, nil
}

func (dn42 DN42) createAAAARecordForNS(ns string, ip string) (*dns.AAAA, error) {
	ipv6 := net.ParseIP(ip)
	if ipv6.To4() != nil {
		return nil, errors.New(ip + " is not a IPv6 address")
	}

	return &dns.AAAA{
		Hdr: dns.RR_Header{
			Name:   ns + ".",
			Rrtype: dns.TypeAAAA,
			Class:  dns.ClassINET,
			Ttl:    dn42.Ttl,
		},
		AAAA: ipv6,
	}, nil
}

func (dn42 DN42) fileExists(folder string, filename string) bool {
	path := filepath.Join(dn42.DN42RegistryPath, "data", folder, filename)
	// TODO: check if path is subdirectory of registry
	_, err := os.Stat(path)
	return err == nil
}

func (dn42 DN42) findDomain(qname string) (string, error) {
	splittedName := dns.SplitDomainName(qname)
	for len(splittedName) > 0 {
		filename := strings.Join(splittedName, ".")
		if dn42.fileExists("dns", filename) {
			return filename, nil
		}
		splittedName = splittedName[1:]
	}
	return "", errors.New(qname + " not found")
}

func (dn42 DN42) parseRegistryFile(qname string, folder string, filename string) ([]dns.RR, []dns.RR, error) {
	path := filepath.Join(dn42.DN42RegistryPath, "data", folder, filename)
	file, err := os.Open(path)
	if err != nil {
		return []dns.RR{}, []dns.RR{}, err
	}

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	var directList []dns.RR
	var nsList []dns.RR
	var extraList []dns.RR
	var seenNS []string

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, NS_PREFIX) {
			nsRecord := strings.SplitN(line[len(NS_PREFIX):], " ", 2)
			ns := strings.TrimSpace(nsRecord[0])
			if !contains(seenNS, ns) {
				rec, err := dn42.createNSRecord(qname, ns)
				if err != nil {
					return []dns.RR{}, []dns.RR{}, err
				}
				nsList = append(nsList, rec)
				seenNS = append(seenNS, ns)
			}

			if len(nsRecord) > 1 {
				ip := strings.TrimSpace(nsRecord[1])
				if strings.Contains(ip, ":") {
					rec, err := dn42.createAAAARecordForNS(ns, ip)
					if err != nil {
						return []dns.RR{}, []dns.RR{}, err
					}
					// Bypass NS lookup if qname points to a NS with IP
					if qname == rec.Header().Name {
						directList = append(directList, rec)
					}
					extraList = append(extraList, rec)
				} else {
					rec, err := dn42.createARecordForNS(ns, ip)
					if err != nil {
						return []dns.RR{}, []dns.RR{}, err
					}
					// Bypass NS lookup if qname points to a NS with IP
					if qname == rec.Header().Name {
						directList = append(directList, rec)
					}
					extraList = append(extraList, rec)
				}
			}
		} else if strings.HasPrefix(line, DS_PREFIX) {
			ds := line[len(DS_PREFIX):]
			rec, err := dn42.createDSRecord(qname, ds)
			if err != nil {
				return []dns.RR{}, []dns.RR{}, err
			}
			nsList = append(nsList, rec)
		}
	}

	if len(directList) != 0 {
		return directList, []dns.RR{}, nil
	}
	return nsList, extraList, nil
}
