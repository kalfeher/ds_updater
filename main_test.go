package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// ── DSKey.String ─────────────────────────────────────────────────────────────

func TestDSKeyString(t *testing.T) {
	k := DSKey{KeyTag: 12345, Algorithm: 8, DigestType: 2, Digest: "ABCDEF01"}
	want := "tag=12345 alg=8 dtype=2 digest=ABCDEF01"
	if got := k.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// ── containsKey ──────────────────────────────────────────────────────────────

func TestContainsKey(t *testing.T) {
	a := DSKey{KeyTag: 1, Algorithm: 8, DigestType: 2, Digest: "AABB"}
	b := DSKey{KeyTag: 2, Algorithm: 13, DigestType: 4, Digest: "CCDD"}
	set := []DSKey{a, b}

	tests := []struct {
		name string
		set  []DSKey
		key  DSKey
		want bool
	}{
		{"first element", set, a, true},
		{"second element", set, b, true},
		{"wrong digest", set, DSKey{KeyTag: 1, Algorithm: 8, DigestType: 2, Digest: "FFFF"}, false},
		{"wrong algorithm", set, DSKey{KeyTag: 1, Algorithm: 5, DigestType: 2, Digest: "AABB"}, false},
		{"wrong key tag", set, DSKey{KeyTag: 99, Algorithm: 8, DigestType: 2, Digest: "AABB"}, false},
		{"nil set", nil, a, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := containsKey(tc.set, tc.key); got != tc.want {
				t.Errorf("containsKey() = %v, want %v", got, tc.want)
			}
		})
	}
}

// ── deleteURL ────────────────────────────────────────────────────────────────

func TestDeleteURL(t *testing.T) {
	tests := []struct {
		name    string
		apiURL  string
		domain  string
		keyTag  uint16
		want    string
		wantErr bool
	}{
		{
			name:   "porkbun-style URL",
			apiURL: "https://api.porkbun.com/api/json/v3/dns/createDnssecRecord",
			domain: "example.com.",
			keyTag: 54467,
			want:   "https://api.porkbun.com/api/json/v3/dns/deleteDnssecRecord/example.com/54467",
		},
		{
			name:   "trailing slash in URL",
			apiURL: "https://api.example.com/v1/dns/addRecord/",
			domain: "test.org.",
			keyTag: 100,
			want:   "https://api.example.com/v1/dns/deleteDnssecRecord/test.org/100",
		},
		{
			name:   "domain without FQDN dot",
			apiURL: "https://api.porkbun.com/api/json/v3/dns/createDnssecRecord",
			domain: "example.com",
			keyTag: 1,
			want:   "https://api.porkbun.com/api/json/v3/dns/deleteDnssecRecord/example.com/1",
		},
		{
			// All path segments contain a dot, so there is no replaceable action segment.
			name:    "no replaceable action segment",
			apiURL:  "https://api.example.com/v1.0/",
			domain:  "example.com",
			keyTag:  1,
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := deleteURL(tc.apiURL, tc.domain, tc.keyTag)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// ── loadConfig ───────────────────────────────────────────────────────────────
// loadConfig calls log.Fatal when DOMAIN is empty, so only valid inputs are tested.

func TestLoadConfig(t *testing.T) {
	t.Run("defaults applied", func(t *testing.T) {
		t.Setenv("DOMAIN", "example.com")
		t.Setenv("RESOLVER", "")
		t.Setenv("DELETE_DS", "")

		cfg := loadConfig()

		if cfg.Domain != "example.com." {
			t.Errorf("Domain = %q, want %q", cfg.Domain, "example.com.")
		}
		if cfg.Resolver != defaultResolver {
			t.Errorf("Resolver = %q, want %q", cfg.Resolver, defaultResolver)
		}
		if cfg.DeleteDS {
			t.Error("DeleteDS should default to false")
		}
	})

	t.Run("resolver without port gets :53 appended", func(t *testing.T) {
		t.Setenv("DOMAIN", "example.com")
		t.Setenv("RESOLVER", "1.1.1.1")
		t.Setenv("DELETE_DS", "")

		cfg := loadConfig()
		if cfg.Resolver != "1.1.1.1:53" {
			t.Errorf("Resolver = %q, want 1.1.1.1:53", cfg.Resolver)
		}
	})

	t.Run("resolver with port unchanged", func(t *testing.T) {
		t.Setenv("DOMAIN", "example.com")
		t.Setenv("RESOLVER", "1.1.1.1:5353")
		t.Setenv("DELETE_DS", "")

		cfg := loadConfig()
		if cfg.Resolver != "1.1.1.1:5353" {
			t.Errorf("Resolver = %q, want 1.1.1.1:5353", cfg.Resolver)
		}
	})

	t.Run("FQDN dot added to domain", func(t *testing.T) {
		t.Setenv("DOMAIN", "sub.example.com")
		t.Setenv("RESOLVER", "")
		t.Setenv("DELETE_DS", "")

		cfg := loadConfig()
		if !strings.HasSuffix(cfg.Domain, ".") {
			t.Errorf("Domain %q should end with '.'", cfg.Domain)
		}
	})

	t.Run("DELETE_DS true", func(t *testing.T) {
		t.Setenv("DOMAIN", "example.com")
		t.Setenv("RESOLVER", "")
		t.Setenv("DELETE_DS", "true")

		cfg := loadConfig()
		if !cfg.DeleteDS {
			t.Error("DeleteDS should be true")
		}
	})

	t.Run("DELETE_DS case-insensitive", func(t *testing.T) {
		t.Setenv("DOMAIN", "example.com")
		t.Setenv("RESOLVER", "")
		t.Setenv("DELETE_DS", "TRUE")

		cfg := loadConfig()
		if !cfg.DeleteDS {
			t.Error("DeleteDS should be true for 'TRUE'")
		}
	})
}

// ── postRecord ───────────────────────────────────────────────────────────────

func TestPostRecord(t *testing.T) {
	key := DSKey{KeyTag: 54467, Algorithm: 8, DigestType: 2, Digest: "ABCD1234"}

	t.Run("sends correct JSON payload", func(t *testing.T) {
		var gotBody map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Errorf("method = %s, want POST", r.Method)
			}
			if ct := r.Header.Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &gotBody)
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		cfg := Config{APIURL: srv.URL, APIKey: "mykey", APISecret: "mysecret"}
		if err := postRecord(cfg, key); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if gotBody["apikey"] != "mykey" {
			t.Errorf("apikey = %v, want mykey", gotBody["apikey"])
		}
		if gotBody["secretapikey"] != "mysecret" {
			t.Errorf("secretapikey = %v, want mysecret", gotBody["secretapikey"])
		}
		// JSON numbers unmarshal as float64.
		if gotBody["key_tag"].(float64) != float64(key.KeyTag) {
			t.Errorf("key_tag = %v, want %d", gotBody["key_tag"], key.KeyTag)
		}
		if gotBody["digest"] != key.Digest {
			t.Errorf("digest = %v, want %s", gotBody["digest"], key.Digest)
		}
	})

	t.Run("non-2xx response returns error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer srv.Close()

		if err := postRecord(Config{APIURL: srv.URL}, key); err == nil {
			t.Error("expected error for 401 response")
		}
	})

	t.Run("empty API_URL returns error", func(t *testing.T) {
		if err := postRecord(Config{}, key); err == nil {
			t.Error("expected error when APIURL is empty")
		}
	})
}

// ── deleteRecord ─────────────────────────────────────────────────────────────

func TestDeleteRecord(t *testing.T) {
	key := DSKey{KeyTag: 12345, Algorithm: 8, DigestType: 2, Digest: "DEADBEEF"}

	t.Run("posts to derived delete URL", func(t *testing.T) {
		var gotPath string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		cfg := Config{
			Domain:    "example.com.",
			APIURL:    srv.URL + "/v1/dns/createDnssecRecord",
			APIKey:    "k",
			APISecret: "s",
		}
		if err := deleteRecord(cfg, key); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := "/v1/dns/deleteDnssecRecord/example.com/12345"
		if gotPath != want {
			t.Errorf("request path = %q, want %q", gotPath, want)
		}
	})

	t.Run("non-2xx response returns error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer srv.Close()

		cfg := Config{
			Domain: "example.com.",
			APIURL: srv.URL + "/v1/dns/createDnssecRecord",
		}
		if err := deleteRecord(cfg, key); err == nil {
			t.Error("expected error for 403 response")
		}
	})

	t.Run("empty API_URL returns error", func(t *testing.T) {
		if err := deleteRecord(Config{Domain: "example.com."}, key); err == nil {
			t.Error("expected error when APIURL is empty")
		}
	})
}

// ── DNS query helpers ────────────────────────────────────────────────────────

// startDNSServer starts a local UDP DNS server on a random port and returns
// its address. The server is shut down automatically when the test ends.
func startDNSServer(t *testing.T, handler dns.Handler) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Net: "udp", Handler: handler}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// ── queryCDS ─────────────────────────────────────────────────────────────────

func TestQueryCDS(t *testing.T) {
	t.Run("returns parsed CDS records with uppercased digest", func(t *testing.T) {
		want := DSKey{KeyTag: 54467, Algorithm: 8, DigestType: 2, Digest: "ABCD1234"}

		addr := startDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeCDS {
				m.Answer = append(m.Answer, &dns.CDS{
					DS: dns.DS{
						Hdr:        dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeCDS, Class: dns.ClassINET, Ttl: 300},
						KeyTag:     want.KeyTag,
						Algorithm:  want.Algorithm,
						DigestType: want.DigestType,
						Digest:     strings.ToLower(want.Digest), // supply lower-case; function must upper-case it
					},
				})
			}
			_ = w.WriteMsg(m)
		}))

		keys, err := queryCDS("example.com.", addr)
		if err != nil {
			t.Fatalf("queryCDS: %v", err)
		}
		if len(keys) != 1 {
			t.Fatalf("got %d keys, want 1", len(keys))
		}
		if keys[0] != want {
			t.Errorf("got %+v, want %+v", keys[0], want)
		}
	})

	t.Run("NXDOMAIN returns empty slice without error", func(t *testing.T) {
		addr := startDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Rcode = dns.RcodeNameError
			_ = w.WriteMsg(m)
		}))

		keys, err := queryCDS("nonexistent.example.com.", addr)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(keys) != 0 {
			t.Errorf("got %d keys, want 0", len(keys))
		}
	})

	t.Run("SERVFAIL returns error", func(t *testing.T) {
		addr := startDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Rcode = dns.RcodeServerFailure
			_ = w.WriteMsg(m)
		}))

		_, err := queryCDS("example.com.", addr)
		if err == nil {
			t.Error("expected error for SERVFAIL response")
		}
	})
}

// ── queryDS ──────────────────────────────────────────────────────────────────

func TestQueryDS(t *testing.T) {
	t.Run("returns parsed DS records with uppercased digest", func(t *testing.T) {
		want := DSKey{KeyTag: 12345, Algorithm: 13, DigestType: 4, Digest: "DEADBEEFCAFE"}

		addr := startDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeDS {
				m.Answer = append(m.Answer, &dns.DS{
					Hdr:        dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 300},
					KeyTag:     want.KeyTag,
					Algorithm:  want.Algorithm,
					DigestType: want.DigestType,
					Digest:     strings.ToLower(want.Digest),
				})
			}
			_ = w.WriteMsg(m)
		}))

		keys, err := queryDS("example.com.", addr)
		if err != nil {
			t.Fatalf("queryDS: %v", err)
		}
		if len(keys) != 1 {
			t.Fatalf("got %d keys, want 1", len(keys))
		}
		if keys[0] != want {
			t.Errorf("got %+v, want %+v", keys[0], want)
		}
	})

	t.Run("NXDOMAIN returns empty slice without error", func(t *testing.T) {
		addr := startDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Rcode = dns.RcodeNameError
			_ = w.WriteMsg(m)
		}))

		keys, err := queryDS("nonexistent.example.com.", addr)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(keys) != 0 {
			t.Errorf("got %d keys, want 0", len(keys))
		}
	})

	t.Run("SERVFAIL returns error", func(t *testing.T) {
		addr := startDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Rcode = dns.RcodeServerFailure
			_ = w.WriteMsg(m)
		}))

		_, err := queryDS("example.com.", addr)
		if err == nil {
			t.Error("expected error for SERVFAIL response")
		}
	})
}
