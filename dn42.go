package dn42

import (
	"context"
	"net"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

// var log = clog.NewWithPlugin("dn42")

type DN42 struct {
	DN42RegistryPath string
	Ttl              uint32
	Next             plugin.Handler
}

// ServeDNS implements the plugin.Handler interface. This method gets called when example is used
// in a Server.
func (dn42 DN42) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	qname := state.QName()

	resp := new(dns.Msg)
	resp.SetReply(r)
	resp.Compress = true

	var domain, filename, newQname string
	var err error
	var ip *net.IP
	var ipMask int
	var nsList, nsList2, extraList []dns.RR

	if ip, ipMask, _ = dn42.parseIPv4Ptr(qname); ip != nil {
		filename, ipMask, err = dn42.findIPv4RecordFile(*ip, ipMask)
		if err != nil {
			goto nextPlugin
		}

		if ipMask > 24 && ipMask < 32 {
			nsList, newQname, err = dn42.generateIPv4CNAMERecord(qname, *ip, ipMask)
			if err != nil {
				goto nextPlugin
			}
		}

		nsList2, extraList, err = dn42.parseRegistryFile(newQname, "inetnum", filename)
		if err != nil {
			goto nextPlugin
		}

		nsList = append(nsList, nsList2...)
	} else if ip, ipMask, _ = dn42.parseIPv6Ptr(qname); ip != nil {
		filename, _, err = dn42.findIPv6RecordFile(*ip, ipMask)
		if err != nil {
			goto nextPlugin
		}

		nsList, extraList, err = dn42.parseRegistryFile(qname, "inet6num", filename)
		if err != nil {
			goto nextPlugin
		}
	} else {
		domain, err = dn42.findDomain(qname)
		if err != nil {
			goto nextPlugin
		}

		nsList, extraList, err = dn42.parseRegistryFile(qname, "dns", domain)
		if err != nil {
			goto nextPlugin
		}
	}

	resp.Ns = nsList
	resp.Extra = extraList

	w.WriteMsg(resp)
	return dns.RcodeSuccess, nil

nextPlugin:
	// Call next plugin (if any).
	return plugin.NextOrFailure(dn42.Name(), dn42.Next, ctx, w, r)
}

// Name implements the Handler interface.
func (dn42 DN42) Name() string { return "dn42" }
