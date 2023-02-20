package dn42

// Ready implements the ready.Readiness interface, once this flips to true CoreDNS
// assumes this plugin is ready for queries; it is not checked again.
func (dn42 DN42) Ready() bool { return true }
