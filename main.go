// ds_updater checks the CDS and DS DNS records for a domain and reconciles them.
//
// Behaviour:
//   - If all CDS records have a matching DS record and vice versa, the program
//     exits without taking any action.
//   - If a CDS record is present with no matching DS record the program sends
//     an HTTP POST to a configurable URL (e.g. a registrar API) so the DS
//     record can be created at the parent zone.
//   - If a DS record is present with no matching CDS record the discrepancy is
//     logged as a warning; no automatic action is taken because removing a DS
//     record without a clear signal from the child zone would break DNSSEC.
//
// Configuration is provided through environment variables:
//
//	DOMAIN      – (required) domain name to check, e.g. "example.com"
//	RESOLVER    – DNS resolver to use (default: 8.8.8.8:53)
//	API_URL     – URL to POST when a CDS record has no matching DS record
//	API_KEY     – API key sent in the POST body
//	API_SECRET  – API secret sent in the POST body
//
//	 DELETE_DS   – set to "true" to DELETE DS records that have no matching CDS record;
//	              the delete URL is derived from API_URL by replacing the action segment
//	              with "deleteDnssecRecord" and appending /{domain}/{keyTag}
//	              (default: false, warning only)
//
// The POST body is a JSON object containing the API credentials and the record
// fields (key_tag, algorithm, digest_type, digest).  Adjust API_URL, API_KEY
// and API_SECRET to match the registrar API you are targeting.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const defaultResolver = "8.8.8.8:53"

// Config holds runtime configuration loaded from environment variables.
type Config struct {
	Domain    string
	Resolver  string
	APIURL    string
	APIKey    string
	APISecret string
	DeleteDS  bool
}

// DSKey is the canonical, comparable representation of a DS or CDS record.
// The Digest field is always stored as upper-case hex so that comparison is
// case-insensitive.
type DSKey struct {
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     string
}

func (k DSKey) String() string {
	return fmt.Sprintf("tag=%d alg=%d dtype=%d digest=%s",
		k.KeyTag, k.Algorithm, k.DigestType, k.Digest)
}

func loadConfig() Config {
	cfg := Config{
		Domain:    os.Getenv("DOMAIN"),
		Resolver:  os.Getenv("RESOLVER"),
		APIURL:    os.Getenv("API_URL"),
		APIKey:    os.Getenv("API_KEY"),
		APISecret: os.Getenv("API_SECRET"),
		DeleteDS:  strings.EqualFold(os.Getenv("DELETE_DS"), "true"),
	}
	if cfg.Domain == "" {
		log.Fatal("DOMAIN environment variable is required")
	}
	if cfg.Resolver == "" {
		cfg.Resolver = defaultResolver
	}
	if !strings.Contains(cfg.Resolver, ":") {
		cfg.Resolver += ":53"
	}
	// dns.Fqdn ensures the name ends with a dot, as required by the DNS library.
	cfg.Domain = dns.Fqdn(cfg.Domain)
	return cfg
}

// queryRRs sends a DNS query for qtype and returns the answer section.
// An NXDOMAIN response is treated as an empty result (not an error) because
// it simply means no records of that type exist.
func queryRRs(domain, resolver string, qtype uint16) ([]dns.RR, error) {
	c := &dns.Client{Timeout: 10 * time.Second}

	m := new(dns.Msg)
	m.SetQuestion(domain, qtype)
	m.RecursionDesired = true
	m.SetEdns0(4096, true) // request DNSSEC records (DO bit)

	r, _, err := c.Exchange(m, resolver)
	if err != nil {
		return nil, fmt.Errorf("DNS exchange: %w", err)
	}
	switch r.Rcode {
	case dns.RcodeSuccess:
		return r.Answer, nil
	case dns.RcodeNameError: // NXDOMAIN – domain exists but record type absent
		return nil, nil
	default:
		return nil, fmt.Errorf("DNS query returned rcode %s", dns.RcodeToString[r.Rcode])
	}
}

func queryCDS(domain, resolver string) ([]DSKey, error) {
	rrs, err := queryRRs(domain, resolver, dns.TypeCDS)
	if err != nil {
		return nil, err
	}
	var keys []DSKey
	for _, rr := range rrs {
		if cds, ok := rr.(*dns.CDS); ok {
			keys = append(keys, DSKey{
				KeyTag:     cds.KeyTag,
				Algorithm:  cds.Algorithm,
				DigestType: cds.DigestType,
				Digest:     strings.ToUpper(cds.Digest),
			})
		}
	}
	return keys, nil
}

func queryDS(domain, resolver string) ([]DSKey, error) {
	rrs, err := queryRRs(domain, resolver, dns.TypeDS)
	if err != nil {
		return nil, err
	}
	var keys []DSKey
	for _, rr := range rrs {
		if ds, ok := rr.(*dns.DS); ok {
			keys = append(keys, DSKey{
				KeyTag:     ds.KeyTag,
				Algorithm:  ds.Algorithm,
				DigestType: ds.DigestType,
				Digest:     strings.ToUpper(ds.Digest),
			})
		}
	}
	return keys, nil
}

// containsKey reports whether set contains an entry equal to key.
// DSKey fields are all comparable so == covers all fields.
func containsKey(set []DSKey, key DSKey) bool {
	for _, k := range set {
		if k == key {
			return true
		}
	}
	return false
}

// postRecord sends the CDS record data and API credentials as a JSON POST to
// cfg.APIURL.  The exact shape of the JSON object matches the field names used
// by the Porkbun API; adjust to suit your registrar if needed.
func postRecord(cfg Config, key DSKey) error {
	if cfg.APIURL == "" {
		return fmt.Errorf("API_URL is not configured; cannot POST DS record")
	}

	payload := map[string]any{
		"apikey":       cfg.APIKey,
		"secretapikey": cfg.APISecret,
		"key_tag":      key.KeyTag,
		"algorithm":    key.Algorithm,
		"digest_type":  key.DigestType,
		"digest":       key.Digest,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, cfg.APIURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP POST: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP POST returned non-2xx status %d", resp.StatusCode)
	}
	return nil
}

// deleteURL derives the DS-deletion endpoint from apiURL by:
//  1. Replacing the action segment (the last non-empty segment that contains no
//     dot) with "deleteDnssecRecord".
//  2. Truncating everything after the action segment.
//  3. Appending /{domain}/{keyTag} so the final URL looks like:
//
//	https://api.porkbun.com/api/json/v3/dns/deleteDnssecRecord/example.com/54467
func deleteURL(apiURL, domain string, keyTag uint16) (string, error) {
	u, err := url.Parse(apiURL)
	if err != nil {
		return "", fmt.Errorf("parse API_URL: %w", err)
	}
	// Split on "/" – the first element is always "" for absolute paths.
	parts := strings.Split(u.Path, "/")
	// Find the last non-empty segment that looks like an action name (no dot),
	// replace it, and truncate everything that follows.
	replaced := false
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] != "" && !strings.Contains(parts[i], ".") {
			parts[i] = "deleteDnssecRecord"
			parts = parts[:i+1] // drop any trailing segments (old domain, key tag, etc.)
			replaced = true
			break
		}
	}
	if !replaced {
		return "", fmt.Errorf("API_URL path has no replaceable action segment: %s", u.Path)
	}
	// Append domain (strip FQDN trailing dot) and key tag.
	domain = strings.TrimSuffix(domain, ".")
	u.Path = strings.Join(parts, "/") + "/" + domain + "/" + fmt.Sprintf("%d", keyTag)
	return u.String(), nil
}

// deleteRecord sends the DS record data and API credentials as a JSON POST to
// the deletion endpoint derived from cfg.APIURL.
func deleteRecord(cfg Config, key DSKey) error {
	if cfg.APIURL == "" {
		return fmt.Errorf("API_URL is not configured; cannot DELETE DS record")
	}

	target, err := deleteURL(cfg.APIURL, cfg.Domain, key.KeyTag)
	if err != nil {
		return err
	}

	payload := map[string]any{
		"apikey":       cfg.APIKey,
		"secretapikey": cfg.APISecret,
		"key_tag":      key.KeyTag,
		"algorithm":    key.Algorithm,
		"digest_type":  key.DigestType,
		"digest":       key.Digest,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP POST: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP POST returned non-2xx status %d", resp.StatusCode)
	}
	return nil
}

func main() {
	cfg := loadConfig()
	log.Printf("domain: %s  resolver: %s", cfg.Domain, cfg.Resolver)

	cdsKeys, err := queryCDS(cfg.Domain, cfg.Resolver)
	if err != nil {
		log.Fatalf("query CDS records: %v", err)
	}
	log.Printf("CDS records found: %d", len(cdsKeys))

	dsKeys, err := queryDS(cfg.Domain, cfg.Resolver)
	if err != nil {
		log.Fatalf("query DS records: %v", err)
	}
	log.Printf("DS  records found: %d", len(dsKeys))

	inSync := true

	// CDS records not present as DS → POST to register them at the parent.
	for _, cds := range cdsKeys {
		if containsKey(dsKeys, cds) {
			continue
		}
		inSync = false
		log.Printf("CDS record has no matching DS record (%s) – posting to %s", cds, cfg.APIURL)
		if err := postRecord(cfg, cds); err != nil {
			log.Printf("ERROR: failed to post DS record: %v", err)
		} else {
			log.Printf("successfully posted DS record: %s", cds)
		}
	}

	// DS records not present as CDS → optionally delete; warn otherwise.
	for _, ds := range dsKeys {
		if containsKey(cdsKeys, ds) {
			continue
		}
		inSync = false
		if cfg.DeleteDS {
			if delURL, urlErr := deleteURL(cfg.APIURL, cfg.Domain, ds.KeyTag); urlErr == nil {
				log.Printf("DS record has no matching CDS record (%s) – deleting via %s", ds, delURL)
			} else {
				log.Printf("DS record has no matching CDS record (%s) – deleting (could not derive URL: %v)", ds, urlErr)
			}
			if err := deleteRecord(cfg, ds); err != nil {
				log.Printf("ERROR: failed to delete DS record: %v", err)
			} else {
				log.Printf("successfully deleted DS record: %s", ds)
			}
		} else {
			log.Printf("WARNING: DS record has no matching CDS record: %s", ds)
		}
	}

	if inSync {
		log.Println("CDS and DS records match – no action taken")
	}
}
