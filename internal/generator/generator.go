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

// GenerateSubdomain creates a deterministic multi-label subdomain.
// Returns something like "a3f8c1d9e2b0.4f71a9c3b2d1.e5f6a7b8c9d0"
func GenerateSubdomain(seed string, utcSecond int64, index int, labelCount, labelLength int) string {
	totalChars := labelCount * labelLength
	hexNeeded := totalChars // hex chars needed

	// Generate enough HMAC output (chain if needed)
	var hexStr string
	for chunk := 0; len(hexStr) < hexNeeded; chunk++ {
		data := fmt.Sprintf("sub:%d:%d:%d", utcSecond, index, chunk)
		mac := hmac.New(sha256.New, []byte(seed))
		mac.Write([]byte(data))
		hash := mac.Sum(nil)
		hexStr += hex.EncodeToString(hash)
	}

	// Split into labels
	labels := make([]string, labelCount)
	for i := 0; i < labelCount; i++ {
		start := i * labelLength
		end := start + labelLength
		labels[i] = hexStr[start:end]
	}

	return strings.Join(labels, ".")
}

// GenerateResponseIP creates a deterministic IP (10.x.y.z) from seed, UTC second, and index.
func GenerateResponseIP(seed string, utcSecond int64, index int) net.IP {
	data := fmt.Sprintf("ip:%d:%d", utcSecond, index)
	mac := hmac.New(sha256.New, []byte(seed))
	mac.Write([]byte(data))
	hash := mac.Sum(nil)
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
// Handles multi-level subdomains: "a.b.c.ns1.example.com." → "a.b.c"
func ExtractSubdomain(queryName, domain string) (string, bool) {
	qn := strings.ToLower(strings.TrimSuffix(queryName, "."))
	dom := strings.ToLower(domain)

	suffix := "." + dom
	if !strings.HasSuffix(qn, suffix) {
		return "", false
	}

	sub := qn[:len(qn)-len(suffix)]
	if sub == "" {
		return "", false
	}

	return sub, true
}
