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
	"syscall"
	"time"

	"github.com/ParsaKSH/Dnstt-DNS-Scanner/internal/config"
	"github.com/ParsaKSH/Dnstt-DNS-Scanner/internal/generator"
	"github.com/miekg/dns"
)

type Server struct {
	cfg   config.Config
	mu    sync.RWMutex
	valid map[string]net.IP // subdomain → response IP
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
	// Keep subdomains valid for timeout + 2s buffer for clock drift
	timeoutSecs := int64(s.cfg.TimeoutMs+999)/1000 + 2
	total := generator.SubdomainsPerSecond(s.cfg.Concurrency, s.cfg.QueryPerSec)

	newValid := make(map[string]net.IP, int(timeoutSecs+1)*total)
	for sec := now - timeoutSecs; sec <= now; sec++ {
		for i := 0; i < total; i++ {
			sub := generator.GenerateSubdomain(s.cfg.Seed, sec, i)
			ip := generator.GenerateResponseIP(s.cfg.Seed, sec, i)
			newValid[sub] = ip
		}
	}

	s.mu.Lock()
	s.valid = newValid
	s.mu.Unlock()
}

// handleDNS processes incoming DNS queries.
func (s *Server) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true
	msg.RecursionAvailable = false

	for _, q := range r.Question {
		if q.Qtype != dns.TypeA {
			continue
		}

		subdomain, ok := generator.ExtractSubdomain(q.Name, s.cfg.Domain)
		if !ok {
			continue
		}

		s.mu.RLock()
		ip, found := s.valid[subdomain]
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

			src := w.RemoteAddr().String()
			if host, _, err := net.SplitHostPort(src); err == nil {
				src = host
			}
			log.Printf("[QUERY] %s → %s from %s", subdomain, ip, src)
		}
	}

	if len(msg.Answer) == 0 {
		msg.Rcode = dns.RcodeNameError
	}

	w.WriteMsg(msg)
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
	fmt.Printf("  UTC Time    : %s\n\n", time.Now().UTC().Format(time.RFC3339))

	// Initial window generation
	srv.regenerateWindow()

	// Regenerate window every 500ms
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for range ticker.C {
			srv.regenerateWindow()
		}
	}()

	// Register handler for our zone
	zone := strings.ToLower(cfg.Domain) + "."
	dns.HandleFunc(zone, srv.handleDNS)

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

	fmt.Printf("  ✓ DNS server listening on %s (zone: %s)\n\n", *listenAddr, zone)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("[FATAL] Server error: %v", err)
	}
}
