package generator

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// GenerateSubdomain creates a deterministic 16-char hex subdomain from seed, UTC second, and index.
func GenerateSubdomain(seed string, utcSecond int64, index int) string {
	data := fmt.Sprintf("sub:%d:%d", utcSecond, index)
	mac := hmac.New(sha256.New, []byte(seed))
	mac.Write([]byte(data))
	hash := mac.Sum(nil)
	return hex.EncodeToString(hash)[:16]
}

// GenerateResponseIP creates a deterministic IP (10.x.y.z) from seed, UTC second, and index.
func GenerateResponseIP(seed string, utcSecond int64, index int) net.IP {
	data := fmt.Sprintf("ip:%d:%d", utcSecond, index)
	mac := hmac.New(sha256.New, []byte(seed))
	mac.Write([]byte(data))
	hash := mac.Sum(nil)
	// Use 10.x.y.z range; ensure non-zero octets for valid IP
	b1 := hash[0]
	b2 := hash[1]
	b3 := hash[2]
	if b3 == 0 {
		b3 = 1
	}
	return net.IPv4(10, b1, b2, b3).To4()
}

// CurrentUTCSecond returns the current UTC unix timestamp (seconds).
func CurrentUTCSecond() int64 {
	return time.Now().UTC().Unix()
}

// SubdomainsPerSecond returns total subdomains generated per second.
func SubdomainsPerSecond(concurrency, qps int) int {
	return concurrency * qps
}

// FQDN builds the fully qualified domain name for a subdomain.
func FQDN(subdomain, domain string) string {
	return subdomain + "." + domain + "."
}

// ExtractSubdomain extracts the subdomain part from a full query name.
// e.g., "abc123.ns1.example.com." with domain "ns1.example.com" → "abc123"
func ExtractSubdomain(queryName, domain string) (string, bool) {
	// Normalize: lowercase, remove trailing dot
	qn := strings.ToLower(strings.TrimSuffix(queryName, "."))
	dom := strings.ToLower(domain)

	suffix := "." + dom
	if !strings.HasSuffix(qn, suffix) {
		return "", false
	}

	sub := qn[:len(qn)-len(suffix)]
	// Must be a single-level subdomain (no dots)
	if strings.Contains(sub, ".") || sub == "" {
		return "", false
	}

	return sub, true
}
