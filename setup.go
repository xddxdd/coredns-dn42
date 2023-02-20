package dn42

import (
	"strconv"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

// init registers this plugin.
func init() { plugin.Register("dn42", setup) }

// setup is the function that gets called when the config parser see the token "example". Setup is responsible
// for parsing any extra options the example plugin may have. The first token this function sees is "example".
func setup(c *caddy.Controller) error {
	var dn42RegistryPath string
	ttl := 3600

	// Skip plugin name
	c.Next()

	// Parse registry path
	if !c.NextArg() {
		// If there was another token, return an error, because we don't have any configuration.
		// Any errors returned from this setup function should be wrapped with plugin.Error, so we
		// can present a slightly nicer error message to the user.
		return plugin.Error("dn42", c.ArgErr())
	} else {
		dn42RegistryPath = c.Val()
	}

	// Parse default TTL
	if c.NextArg() {
		var err error
		ttl, err = strconv.Atoi(c.Val())
		if err != nil {
			return err
		}
	}

	// Error if extra parameters passed
	if c.NextArg() {
		return plugin.Error("dn42", c.ArgErr())
	}

	// Add the Plugin to CoreDNS, so Servers can use it in their plugin chain.
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return DN42{
			DN42RegistryPath: dn42RegistryPath,
			Ttl:              uint32(ttl),
			Next:             next,
		}
	})

	// All OK, return a nil error.
	return nil
}
