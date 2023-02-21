# CoreDNS-DN42

A CoreDNS plugin for serving the DN42 registry.

This plugin acts as an authoritative server. It returns NS & DS records for forward zones and reverse IPv4/IPv6 zones in DN42 registry. It doesn't do any recursion, you need a separate DNS resolver for that.

## WARNING

This plugin is **experimental**. While it appears to work for forward and reverse IPv4/IPv6 DNS, it isn't fully compliant with DNS protocol specs. Compatibility with DNS clients isn't guaranteed.

## Compilation

In your cloned [CoreDNS](https://github.com/coredns/coredns) repository:

1. Add `dn42:github.com/xddxdd/coredns-dn42` to the end of plugin.cfg
2. `go get github.com/xddxdd/coredns-dn42`
3. `go generate`
4. `go build`

## Usage

```
. {
  dn42 "/path/to/dn42/registry" 900
}
```

First argument (mandatory) is the path to DN42 registry. Inside the registry path, there should be a `data` folder containing all IPs and domains.

Second argument (optional) is the default TTL. If unset, default TTL is 3600.

## License

Apache 2.0 license.
