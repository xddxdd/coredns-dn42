package dn42

import "testing"

func TestRegistryPrefixLength(t *testing.T) {
	if len(NS_PREFIX) != 20 {
		t.Errorf("Incorrect len(NS_PREFIX): expected 20, got %d", len(NS_PREFIX))
	}
	if len(DS_PREFIX) != 20 {
		t.Errorf("Incorrect len(DS_PREFIX): expected 20, got %d", len(DS_PREFIX))
	}
}
