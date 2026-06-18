package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const defaultResolver = "1.1.1.1:53"

// Config holds runtime configuration loaded from environment variables.
type Config struct {
	Domain    string
	Resolver  string
	APIURL    string
	APIKey    string
	APISecret string
	DeleteDS  bool
}
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
	if cfg.Resolver == "" {
		cfg.Resolver = defaultResolver
	}
	if cfg.APIURL == "" {
		cfg.APIURL = "https://api.porkbun.com/api/json/v3"
	}
	if cfg.Domain == "" || cfg.APIKey == "" || cfg.APISecret == "" {
		log.Fatal("DOMAIN, API_KEY, and API_SECRET environment variables must be set")
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

func containsKey(set []DSKey, key DSKey) bool {
	for _, k := range set {
		if k == key {
			return true
		}
	}
	return false
}
func postRecord(cfg Config, key DSKey) error {
	apiRoute := "dns/createDnssecRecord"
	domain := strings.TrimSuffix(cfg.Domain, ".") // API expects domain without trailing dot
	requestUrl := fmt.Sprintf("%s/%s/%s", cfg.APIURL, apiRoute, domain)
	log.Printf("CDS record has no matching DS record (%s) – posting to %s", key, requestUrl)
	//		"apikey":       "` + cfg.APIKey + `",
	//	"secretapikey": "` + cfg.APISecret + `",

	payload := strings.NewReader(`{
		"apikey":       "",
		"secretapikey": "",
		"key_tag":      ` + fmt.Sprint(key.KeyTag) + `,
		"algorithm":    ` + fmt.Sprint(key.Algorithm) + `,
		"digest_type":  ` + fmt.Sprint(key.DigestType) + `,
		"digest":       "` + key.Digest + `",
		"maxSigLife": "",
		"keyDataFlags": "",
		"keyDataProtocol": "",
		"keyDataAlgo": "",
		"keyDataPubKey": ""
	}`)
	req, err := http.NewRequest("POST", requestUrl, payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-API-Key", cfg.APIKey)
	req.Header.Add("X-Secret-API-Key", cfg.APISecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error: status %d, response: %s payload: %s", resp.StatusCode, string(respBody), payload)
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
	// print the tag and digest of each CDS record found
	for _, k := range cdsKeys {
		log.Printf("CDS record: %s", k.String())
	}
	log.Printf("CDS records found: %d", len(cdsKeys))

	dsKeys, err := queryDS(cfg.Domain, cfg.Resolver)
	if err != nil {
		log.Fatalf("query DS records: %v", err)
	}
	// print the tag and digest of each DS record found
	for _, k := range dsKeys {
		log.Printf("DS  record: %s", k.String())
	}
	log.Printf("DS  records found: %d", len(dsKeys))
	inSync := true

	// CDS records not present as DS → POST to register them at the parent.
	for _, cds := range cdsKeys {
		if containsKey(dsKeys, cds) {
			continue
		}
		inSync = false

		if err := postRecord(cfg, cds); err != nil {
			log.Printf("ERROR: failed to post DS record: %v", err)
		} else {
			log.Printf("successfully posted DS record: %s", cds)
		}
	}

	if inSync {
		log.Printf("CDS and DS records are in sync – no action needed")
	} else {
		log.Printf("CDS and DS records are not in sync – posted missing DS records to parent")
	}
}
