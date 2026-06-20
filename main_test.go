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

// testConfig returns a Config pointed at the given server URL, with the
// domain already in FQDN form so TrimSuffix in the functions under test
// produces "example.com".
func testConfig(serverURL string) Config {
	return Config{
		Domain:    "example.com.",
		APIKey:    "testkey",
		APISecret: "testsecret",
		APIURL:    serverURL,
	}
}

// startDNSServer starts a local UDP DNS server using the provided handler and
// returns its address.  The server is shut down when the test finishes.
func startDNSServer(t *testing.T, handler dns.HandlerFunc) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Net: "udp", Handler: handler}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String()
}

// --- DSKey.String ---

func TestDSKeyString(t *testing.T) {
	k := DSKey{KeyTag: 1234, Algorithm: 13, DigestType: 2, Digest: "ABCDEF"}
	want := "tag=1234 alg=13 dtype=2 digest=ABCDEF"
	if got := k.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// --- containsKey ---

func TestContainsKey_Present(t *testing.T) {
	a := DSKey{KeyTag: 1, Algorithm: 13, DigestType: 2, Digest: "AA"}
	b := DSKey{KeyTag: 2, Algorithm: 13, DigestType: 2, Digest: "BB"}
	if !containsKey([]DSKey{a, b}, a) {
		t.Error("expected to find key a in set")
	}
	if !containsKey([]DSKey{a, b}, b) {
		t.Error("expected to find key b in set")
	}
}

func TestContainsKey_Absent(t *testing.T) {
	a := DSKey{KeyTag: 1, Algorithm: 13, DigestType: 2, Digest: "AA"}
	if containsKey([]DSKey{a}, DSKey{KeyTag: 99}) {
		t.Error("did not expect to find absent key")
	}
}

func TestContainsKey_EmptySet(t *testing.T) {
	if containsKey(nil, DSKey{KeyTag: 1}) {
		t.Error("did not expect to find key in nil set")
	}
	if containsKey([]DSKey{}, DSKey{KeyTag: 1}) {
		t.Error("did not expect to find key in empty set")
	}
}

// TestContainsKey_AllFieldsMustMatch verifies that a key with the same tag but
// different digest is not considered a match.
func TestContainsKey_AllFieldsMustMatch(t *testing.T) {
	a := DSKey{KeyTag: 1, Algorithm: 13, DigestType: 2, Digest: "AA"}
	diff := DSKey{KeyTag: 1, Algorithm: 13, DigestType: 2, Digest: "BB"}
	if containsKey([]DSKey{a}, diff) {
		t.Error("keys with different digest should not match")
	}
}

// --- postRecord ---

func TestPostRecord_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"SUCCESS"}`))
	}))
	defer srv.Close()

	key := DSKey{KeyTag: 8959, Algorithm: 13, DigestType: 2, Digest: "AABBCC"}
	if err := postRecord(testConfig(srv.URL), key); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPostRecord_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"status":"ERROR","message":"bad request"}`))
	}))
	defer srv.Close()

	err := postRecord(testConfig(srv.URL), DSKey{KeyTag: 1, Algorithm: 13, DigestType: 2, Digest: "AA"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("expected status 400 in error message, got: %v", err)
	}
}

// TestPostRecord_PayloadFields verifies that the correct JSON field names are
// sent (keyTag / alg / digestType) and the previously-wrong names are absent.
func TestPostRecord_PayloadFields(t *testing.T) {
	var gotBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &gotBody)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"SUCCESS"}`))
	}))
	defer srv.Close()

	key := DSKey{KeyTag: 8959, Algorithm: 13, DigestType: 2, Digest: "DEADBEEF"}
	postRecord(testConfig(srv.URL), key)

	want := map[string]string{
		"keyTag":     "8959",
		"alg":        "13",
		"digestType": "2",
		"digest":     "DEADBEEF",
	}
	for field, wantVal := range want {
		if got := gotBody[field]; got != wantVal {
			t.Errorf("field %q: got %q, want %q", field, got, wantVal)
		}
	}
	for _, bad := range []string{"key_tag", "algorithm", "digest_type"} {
		if _, ok := gotBody[bad]; ok {
			t.Errorf("unexpected legacy field %q present in payload", bad)
		}
	}
}

func TestPostRecord_RequestURL(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"SUCCESS"}`))
	}))
	defer srv.Close()

	postRecord(testConfig(srv.URL), DSKey{KeyTag: 1, Algorithm: 13, DigestType: 2, Digest: "AA"})

	want := "/dns/createDnssecRecord/example.com"
	if gotPath != want {
		t.Errorf("got path %q, want %q", gotPath, want)
	}
}

func TestPostRecord_ContentTypeHeader(t *testing.T) {
	var gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"SUCCESS"}`))
	}))
	defer srv.Close()

	postRecord(testConfig(srv.URL), DSKey{KeyTag: 1, Algorithm: 13, DigestType: 2, Digest: "AA"})

	if gotCT != "application/json" {
		t.Errorf("Content-Type: got %q, want %q", gotCT, "application/json")
	}
}

// --- deleteRecord ---

func TestDeleteRecord_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"SUCCESS"}`))
	}))
	defer srv.Close()

	key := DSKey{KeyTag: 8959, Algorithm: 13, DigestType: 2, Digest: "AABBCC"}
	if err := deleteRecord(testConfig(srv.URL), key); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteRecord_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"status":"ERROR","message":"not found"}`))
	}))
	defer srv.Close()

	err := deleteRecord(testConfig(srv.URL), DSKey{KeyTag: 1, Algorithm: 13, DigestType: 2, Digest: "AA"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("expected status 400 in error message, got: %v", err)
	}
}

// TestDeleteRecord_URLContainsKeyTag verifies the key tag appears as the final
// path segment of the delete URL.
func TestDeleteRecord_URLContainsKeyTag(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"SUCCESS"}`))
	}))
	defer srv.Close()

	deleteRecord(testConfig(srv.URL), DSKey{KeyTag: 8959, Algorithm: 13, DigestType: 2, Digest: "AA"})

	want := "/dns/deleteDnssecRecord/example.com/8959"
	if gotPath != want {
		t.Errorf("got path %q, want %q", gotPath, want)
	}
}

// --- queryCDS / queryDS ---

func TestQueryCDS_RecordFound(t *testing.T) {
	handler := func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.CDS{
			DS: dns.DS{
				Hdr:        dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeCDS, Class: dns.ClassINET, Ttl: 300},
				KeyTag:     8959,
				Algorithm:  13,
				DigestType: 2,
				Digest:     "deadbeef",
			},
		})
		w.WriteMsg(m)
	}
	addr := startDNSServer(t, handler)

	keys, err := queryCDS("example.com.", addr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 CDS key, got %d", len(keys))
	}
	if keys[0].KeyTag != 8959 {
		t.Errorf("KeyTag: got %d, want 8959", keys[0].KeyTag)
	}
	if keys[0].Digest != "DEADBEEF" {
		t.Errorf("Digest: got %q, want %q (must be uppercased)", keys[0].Digest, "DEADBEEF")
	}
}

func TestQueryDS_RecordFound(t *testing.T) {
	handler := func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.DS{
			Hdr:        dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 300},
			KeyTag:     1234,
			Algorithm:  13,
			DigestType: 2,
			Digest:     "cafebabe",
		})
		w.WriteMsg(m)
	}
	addr := startDNSServer(t, handler)

	keys, err := queryDS("example.com.", addr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 DS key, got %d", len(keys))
	}
	if keys[0].KeyTag != 1234 {
		t.Errorf("KeyTag: got %d, want 1234", keys[0].KeyTag)
	}
	if keys[0].Digest != "CAFEBABE" {
		t.Errorf("Digest: got %q, want %q (must be uppercased)", keys[0].Digest, "CAFEBABE")
	}
}

func TestQueryCDS_NXDOMAIN(t *testing.T) {
	handler := func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNameError)
		w.WriteMsg(m)
	}
	addr := startDNSServer(t, handler)

	keys, err := queryCDS("nonexistent.example.", addr)
	if err != nil {
		t.Fatalf("expected nil error for NXDOMAIN, got: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected empty result for NXDOMAIN, got %d keys", len(keys))
	}
}

func TestQueryDS_EmptyAnswer(t *testing.T) {
	handler := func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r) // NOERROR, no answer RRs
		w.WriteMsg(m)
	}
	addr := startDNSServer(t, handler)

	keys, err := queryDS("example.com.", addr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 DS keys, got %d", len(keys))
	}
}

func TestQueryCDS_MultipleRecords(t *testing.T) {
	handler := func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		for _, tag := range []uint16{100, 200, 300} {
			m.Answer = append(m.Answer, &dns.CDS{
				DS: dns.DS{
					Hdr:        dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeCDS, Class: dns.ClassINET, Ttl: 300},
					KeyTag:     tag,
					Algorithm:  13,
					DigestType: 2,
					Digest:     "aabb",
				},
			})
		}
		w.WriteMsg(m)
	}
	addr := startDNSServer(t, handler)

	keys, err := queryCDS("example.com.", addr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 3 {
		t.Errorf("expected 3 CDS keys, got %d", len(keys))
	}
}

func TestQueryRRs_ServerError(t *testing.T) {
	handler := func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
	}
	addr := startDNSServer(t, handler)

	_, err := queryCDS("example.com.", addr)
	if err == nil {
		t.Fatal("expected error for SERVFAIL, got nil")
	}
	if !strings.Contains(err.Error(), "SERVFAIL") {
		t.Errorf("expected SERVFAIL in error, got: %v", err)
	}
}
