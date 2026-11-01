package policy

import (
	"encoding/base64"
	"net"
	"testing"
)

func peer(ip string) net.Addr {
	return &net.TCPAddr{IP: net.ParseIP(ip), Port: 51000}
}

// b64 is the test-side encoding of user:pass (same as production encoding).
func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestAdmitClientApproved(t *testing.T) {
	g, err := NewGate([]string{"192.168.0.25"}, "mhi")
	if err != nil {
		t.Fatal(err)
	}
	if g.AdmitClient(peer("192.168.0.25")) != Allow {
		t.Fatal("approved client must pass")
	}
}

func TestAdmitClientUnapproved(t *testing.T) {
	g, _ := NewGate([]string{"192.168.0.25"}, "mhi")
	if g.AdmitClient(peer("192.168.0.26")) != DenyClient {
		t.Fatal("unapproved peer must be denied (AC-08)")
	}
}

func TestAdmitClientEmptyListDenies(t *testing.T) {
	g, _ := NewGate(nil, "mhi")
	if g.AdmitClient(peer("192.168.0.25")) != DenyClient {
		t.Fatal("empty approved list must fail closed")
	}
}

func TestNewGateRejectsHostname(t *testing.T) {
	if _, err := NewGate([]string{"iphone.local"}, "mhi"); err == nil {
		t.Fatal("hostname client entries must be rejected (IP-only §4.5)")
	}
}

func TestAuthorize(t *testing.T) {
	a, err := NewAuth("mhi", "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	// Build the expected header externally (mirrors what a proxy client sends).
	u, p := "mhi", "s3cret"
	want := "Basic " + b64(u+":"+p)
	if !a.Authorize(want) {
		t.Fatal("valid credentials must authorize")
	}
	if a.Authorize("") {
		t.Fatal("empty header must fail closed")
	}
	if a.Authorize("Basic wrongtoken") {
		t.Fatal("invalid credentials must fail")
	}
	if a.Authorize("Bearer " + b64(u+":"+p)) {
		t.Fatal("wrong scheme must fail")
	}
}

func TestDestinationHostPort(t *testing.T) {
	d := DefaultDestination()
	h, port, adm, err := d.CheckHostPort("api.example.com:443")
	if err != nil || adm != Allow {
		t.Fatalf("443 must be allowed: %v %v", adm, err)
	}
	if h != "api.example.com" || port != 443 {
		t.Fatalf("host=%q port=%d", h, port)
	}
}

func TestDestinationMissingPortRejected(t *testing.T) {
	d := DefaultDestination()
	_, _, _, err := d.CheckHostPort("api.example.com")
	if err == nil {
		t.Fatal("missing port must NOT default to 80 (§6)")
	}
}

func TestDestinationBadPortRejected(t *testing.T) {
	d := DefaultDestination()
	if _, _, _, err := d.CheckHostPort("api.example.com:0"); err == nil {
		t.Fatal("port 0 must be refused")
	}
	if _, _, _, err := d.CheckHostPort("api.example.com:99999"); err == nil {
		t.Fatal("port > 65535 must be refused")
	}
	if _, _, _, err := d.CheckHostPort("api.example.com:smtp"); err == nil {
		t.Fatal("service-name ports must be refused (§6: no SMTP/any port)")
	}
}

func TestDestinationPrivateBlocked(t *testing.T) {
	d := DefaultDestination()
	for _, a := range []string{
		"127.0.0.1:443", "10.0.0.3:443", "192.168.1.1:443",
		"169.254.169.254:443", "fe80::1:443", "::1:443",
		"localhost:443",
	} {
		if _, _, adm, _ := d.CheckHostPort(a); adm == Allow {
			t.Fatalf("%s must be blocked (§6 outbound restrictions)", a)
		}
	}
}

func TestDestinationPublicAllowed(t *testing.T) {
	d := DefaultDestination()
	if _, _, adm, err := d.CheckHostPort("api.github.com:443"); adm != Allow || err != nil {
		t.Fatalf("public 443 must be allowed: %v %v", adm, err)
	}
}
