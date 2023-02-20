package dn42

import (
	"context"
	"net"

	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

// Define log to be a logger with the plugin name in it. This way we can just use log.Info and
// friends to log.
var log = clog.NewWithPlugin("dn42")

// DN42 is an example plugin to show how to write a plugin.
type DN42 struct {
	DN42RegistryPath string
	Ttl              uint32
	Next             plugin.Handler
}

// ServeDNS implements the plugin.Handler interface. This method gets called when example is used
// in a Server.
func (dn42 DN42) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	// This function could be simpler. I.e. just fmt.Println("example") here, but we want to show
	// a slightly more complex example as to make this more interesting.
	// Here we wrap the dns.ResponseWriter in a new ResponseWriter and call the next plugin, when the
	// answer comes back, it will print "example".

	state := request.Request{W: w, Req: r}
	qname := state.QName()

	resp := new(dns.Msg)
	resp.SetReply(r)
	resp.Authoritative = true

	var domain string
	var nsList, nsList2, extraList []dns.RR
	var err error
	var ip *net.IP
	var cidr *net.IPNet
	var filename string
	var newQname string

	if ip, _ = dn42.parseIPv4Ptr(qname); ip != nil {
		filename, cidr, err = dn42.findIPv4RecordFile(*ip)
		if cidr == nil || err != nil {
			goto nextPlugin
		}

		if maskLength := dn42.maskLength(*cidr); maskLength > 24 && maskLength < 32 {
			nsList, newQname, err = dn42.generateIPv4CNAMERecord(qname, *ip, *cidr)
			if err != nil {
				goto nextPlugin
			}

			nsList2, extraList, err = dn42.parseRegistryFile(newQname, "inetnum", filename)
			if err != nil {
				goto nextPlugin
			}

			nsList = append(nsList, nsList2...)
		} else {
			nsList, extraList, err = dn42.parseRegistryFile(qname, "inetnum", filename)
			if err != nil {
				goto nextPlugin
			}
		}
	} else if cidr, _ = dn42.parseIPv4CIDRPtr(qname); cidr != nil {
		filename, cidr, err = dn42.findIPv4CIDRRecordFile(*cidr)
		if cidr == nil || err != nil {
			goto nextPlugin
		}

		nsList, extraList, err = dn42.parseRegistryFile(qname, "inetnum", filename)
		if err != nil {
			goto nextPlugin
		}
	} else if ip, _ = dn42.parseIPv6Ptr(qname); ip != nil {
		filename, cidr, err = dn42.findIPv6RecordFile(*ip)
		if cidr == nil || err != nil {
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
