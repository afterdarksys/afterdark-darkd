package packages

import "testing"

func TestUpdateParsers(t *testing.T) {
	p, err := APT("Reading package lists...\nInst openssl [1.0] (1.1 Ubuntu:stable [amd64])\n")
	if err != nil || len(p) != 1 || p[0].ID != "openssl@1.1" {
		t.Fatal(p, err)
	}
	if _, err := APT("Inst broken"); err == nil {
		t.Fatal("malformed candidate accepted")
	}
	p, err = DNF("Last metadata expiration check: today\nopenssl.x86_64 3.0-1 updates\n")
	if err != nil || len(p) != 1 {
		t.Fatal(p, err)
	}
	p, err = Installed("openssl|||3.0\n")
	if err != nil || len(p) != 1 || p[0].ID != "openssl@3.0" {
		t.Fatal(p, err)
	}
}
