package config

import (
	"errors"
	"testing"
)

func TestDefaultsIsValidMonitoringState(t *testing.T) {
	c := Defaults()
	if c.Listen != "127.0.0.1:9090" {
		t.Fatalf("default listen = %q, want 127.0.0.1:9090", c.Listen)
	}
	if c.SSLProxy.Enabled || len(c.SSLProxy.Domains) != 0 {
		t.Fatal("defaults must be SSL disabled + empty domains (AC-27)")
	}
	if err := validate(c); err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}
}

func TestDecodeMinimal(t *testing.T) {
	got, err := DecodeYAML([]byte("schema_version: 1\nlisten: 127.0.0.1:9090\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Listen != "127.0.0.1:9090" {
		t.Fatalf("listen = %q", got.Listen)
	}
}

func TestDecodeUnknownFieldRejected(t *testing.T) {
	_, err := DecodeYAML([]byte("schema_version: 1\nlisten: h:1\nbogus: true\n"))
	if err == nil {
		t.Fatal("unknown field must be rejected (§4.4)")
	}
}

func TestDecodeSecondDocumentRejected(t *testing.T) {
	_, err := DecodeYAML([]byte("schema_version: 1\n---\nfoo: 1\n"))
	if err == nil {
		t.Fatal("multi-document rejected")
	}
}

func TestEnabledWithEmptyDomainsRejected(t *testing.T) {
	_, err := DecodeYAML([]byte("schema_version: 1\nlisten: h:1\nssl_proxy:\n  enabled: true\n  domains: []\n"))
	if !errors.Is(err, ErrEmptySSLList) {
		t.Fatalf("want ErrEmptySSLList, got %v", err)
	}
}

func TestWildcardDomainRejected(t *testing.T) {
	_, err := DecodeYAML([]byte("schema_version: 1\nlisten: h:1\nssl_proxy:\n  enabled: true\n  domains: [\"*.example.com\"]\n"))
	if err == nil {
		t.Fatal("wildcard must be rejected")
	}
}

func TestURLDomainRejected(t *testing.T) {
	_, err := DecodeYAML([]byte("schema_version: 1\nlisten: h:1\nssl_proxy:\n  enabled: true\n  domains: [\"https://api.example.com\"]\n"))
	if err == nil {
		t.Fatal("URL input must be rejected (§4.2)")
	}
}

func TestTooManyDomainsRejected(t *testing.T) {
	if err := validate(Config{
		Listen: "h:1",
		SSLProxy: SSLProxy{Domains: make([]string, MaxDomainEntries+1)},
	}); !errors.Is(err, ErrTooManyDomains) {
		t.Fatalf("want ErrTooManyDomains, got %v", err)
	}
}

func TestFalseWithValidListIsLegalMonitoringState(t *testing.T) {
	// §4.4 table row 2: enabled=false with a valid list is retained-but-idle.
	_, err := DecodeYAML([]byte(
		"schema_version: 1\nlisten: h:1\nssl_proxy:\n  enabled: false\n  domains: [api.example.com]\n"))
	if err != nil {
		t.Fatalf("false + valid list must be accepted: %v", err)
	}
}
