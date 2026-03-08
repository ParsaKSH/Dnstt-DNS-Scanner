package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ParsaKSH/Dnstt-DNS-Scanner/internal/config"
	"github.com/ParsaKSH/Dnstt-DNS-Scanner/internal/generator"
	"github.com/miekg/dns"
)

type Server struct {
	cfg      config.Config
	mu       sync.RWMutex
	valid    map[string]net.IP // subdomain → response IP
	mapSize  int
	totalReq int64
	matchReq int64
}

func NewServer(cfg config.Config) *Server {
	return &Server{
		cfg:   cfg,
		valid: make(map[string]net.IP),
	}
}

// regenerateWindow rebuilds the valid subdomain map for the current time window.
func (s *Server) regenerateWindow() {
	now := generator.CurrentUTCSecond()
	// Keep subdomains valid for timeout + 5s buffer for clock drift and resolver delay
	timeoutSecs := int64(s.cfg.TimeoutMs+999)/1000 + 5
	total := generator.SubdomainsPerSecond(s.cfg.Concurrency, s.cfg.QueryPerSec)

	newValid := make(map[string]net.IP, int(timeoutSecs+1)*total)
	for sec := now - timeoutSecs; sec <= now+2; sec++ { // also generate 2 seconds into future
		for i := 0; i < total; i++ {
			sub := generator.GenerateSubdomain(s.cfg.Seed, sec, i)
			ip := generator.GenerateResponseIP(s.cfg.Seed, sec, i)
			newValid[sub] = ip
		}
	}

	s.mu.Lock()
	s.valid = newValid
	s.mapSize = len(newValid)
	s.mu.Unlock()
}

// handleDNS processes incoming DNS queries.
func (s *Server) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true
	msg.RecursionAvailable = false

	atomic.AddInt64(&s.totalReq, 1)

	for _, q := range r.Question {
		src := w.RemoteAddr().String()
		if host, _, err := net.SplitHostPort(src); err == nil {
			src = host
		}

		if q.Qtype != dns.TypeA {
			log.Printf("[SKIP] non-A query type=%d name=%s from %s", q.Qtype, q.Name, src)
			continue
		}

		subdomain, ok := generator.ExtractSubdomain(q.Name, s.cfg.Domain)
		if !ok {
			log.Printf("[MISS] cannot extract subdomain from %s (domain=%s) from %s", q.Name, s.cfg.Domain, src)
			continue
		}

		s.mu.RLock()
		ip, found := s.valid[subdomain]
		mapSize := s.mapSize
		s.mu.RUnlock()

		if found {
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    0,
				},
				A: ip,
			}
			msg.Answer = append(msg.Answer, rr)
			atomic.AddInt64(&s.matchReq, 1)
			log.Printf("[HIT]  %s → %s from %s", subdomain, ip, src)
		} else {
			log.Printf("[MISS] subdomain=%s NOT in valid map (map_size=%d) from %s", subdomain, mapSize, src)
		}
	}

	if len(msg.Answer) == 0 {
		msg.Rcode = dns.RcodeNameError
	}

	if err := w.WriteMsg(msg); err != nil {
		log.Printf("[ERROR] WriteMsg failed: %v", err)
	}
}

func main() {
	// Server-specific flags (parsed before config.LoadConfig)
	listenAddr := flag.String("listen", ":53", "Listen address (e.g. :53 or 0.0.0.0:5353)")

	cfg := config.LoadConfig()
	srv := NewServer(cfg)

	fmt.Println("┌──────────────────────────────────────────────────┐")
	fmt.Println("│       Dnstt DNS Scanner - Server v2.0            │")
	fmt.Println("└──────────────────────────────────────────────────┘")
	fmt.Printf("  Domain      : %s\n", cfg.Domain)
	fmt.Printf("  Seed        : %s\n", cfg.Seed)
	fmt.Printf("  Listen      : %s\n", *listenAddr)
	fmt.Printf("  Concurrency : %d\n", cfg.Concurrency)
	fmt.Printf("  QPS         : %d\n", cfg.QueryPerSec)
	fmt.Printf("  Timeout     : %dms\n", cfg.TimeoutMs)
	fmt.Printf("  Subs/sec    : %d\n", cfg.Concurrency*cfg.QueryPerSec)
	fmt.Printf("  UTC Time    : %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Printf("  UTC Unix    : %d\n\n", time.Now().UTC().Unix())

	// Print sample subdomains for current second (for debugging sync)
	utcSec := generator.CurrentUTCSecond()
	fmt.Printf("  Sample subdomains for UTC second %d:\n", utcSec)
	for i := 0; i < 3; i++ {
		sub := generator.GenerateSubdomain(cfg.Seed, utcSec, i)
		ip := generator.GenerateResponseIP(cfg.Seed, utcSec, i)
		fmt.Printf("    [%d] %s.%s → %s\n", i, sub, cfg.Domain, ip)
	}
	fmt.Println()

	// Initial window generation
	srv.regenerateWindow()
	srv.mu.RLock()
	fmt.Printf("  Valid map size: %d subdomains\n", srv.mapSize)
	srv.mu.RUnlock()

	// Regenerate window every 500ms
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for range ticker.C {
			srv.regenerateWindow()
		}
	}()

	// Stats ticker - print stats every 5 seconds
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			total := atomic.LoadInt64(&srv.totalReq)
			match := atomic.LoadInt64(&srv.matchReq)
			srv.mu.RLock()
			ms := srv.mapSize
			srv.mu.RUnlock()
			fmt.Printf("  [STATS] UTC=%d | requests=%d | matches=%d | map_size=%d\n",
				generator.CurrentUTCSecond(), total, match, ms)
		}
	}()

	// Register handler for our zone
	zone := strings.ToLower(cfg.Domain) + "."
	dns.HandleFunc(zone, srv.handleDNS)

	// Also register catch-all for debugging
	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		for _, q := range r.Question {
			log.Printf("[UNHANDLED] query for %s (type=%d) - not in zone %s", q.Name, q.Qtype, zone)
		}
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Rcode = dns.RcodeRefused
		w.WriteMsg(msg)
	})

	// Start DNS server
	server := &dns.Server{Addr: *listenAddr, Net: "udp"}

	// Graceful shutdown on SIGINT/SIGTERM
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		fmt.Println("\n  Shutting down server...")
		server.Shutdown()
	}()

	fmt.Printf("\n  ✓ DNS server listening on %s (zone: %s)\n\n", *listenAddr, zone)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("[FATAL] Server error: %v", err)
	}
}
