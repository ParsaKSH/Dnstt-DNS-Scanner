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
	valid    map[string]net.IP
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

func (s *Server) regenerateWindow() {
	now := generator.CurrentUTCSecond()
	timeoutSecs := int64(s.cfg.TimeoutMs+999)/1000 + 5
	total := generator.SubdomainsPerSecond(s.cfg.Concurrency, s.cfg.QueryPerSec)

	newValid := make(map[string]net.IP, int(timeoutSecs+3)*total)
	for sec := now - timeoutSecs; sec <= now+2; sec++ {
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

func (s *Server) handlePacket(conn net.PacketConn, addr net.Addr, buf []byte) {
	atomic.AddInt64(&s.totalReq, 1)

	// Parse incoming DNS message
	req := new(dns.Msg)
	if err := req.Unpack(buf); err != nil {
		log.Printf("[ERROR] Failed to unpack DNS message from %s: %v", addr, err)
		return
	}

	// Build response
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.RecursionAvailable = false

	for _, q := range req.Question {
		src := addr.String()
		if host, _, err := net.SplitHostPort(src); err == nil {
			src = host
		}

		if q.Qtype != dns.TypeA {
			continue
		}

		subdomain, ok := generator.ExtractSubdomain(q.Name, s.cfg.Domain)
		if !ok {
			log.Printf("[MISS] cannot extract subdomain from %s (domain=%s) from %s", q.Name, s.cfg.Domain, src)
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
			resp.Answer = append(resp.Answer, rr)
			atomic.AddInt64(&s.matchReq, 1)
			log.Printf("[HIT]  %s → %s from %s", subdomain, ip, src)
		} else {
			log.Printf("[MISS] subdomain=%s NOT in valid map (map_size=%d) from %s", subdomain, s.mapSize, src)
		}
	}

	if len(resp.Answer) == 0 {
		resp.Rcode = dns.RcodeNameError
	}

	// Pack and send response
	out, err := resp.Pack()
	if err != nil {
		log.Printf("[ERROR] Failed to pack DNS response: %v", err)
		return
	}

	if _, err := conn.WriteTo(out, addr); err != nil {
		log.Printf("[ERROR] Failed to send DNS response to %s: %v", addr, err)
	}
}

func main() {
	listenAddr := flag.String("listen", "0.0.0.0:53", "Listen address")

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

	// Print sample subdomains
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
	fmt.Printf("  Valid map size: %d subdomains\n", srv.mapSize)

	// Regenerate window every 500ms
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for range ticker.C {
			srv.regenerateWindow()
		}
	}()

	// Stats ticker
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			total := atomic.LoadInt64(&srv.totalReq)
			match := atomic.LoadInt64(&srv.matchReq)
			fmt.Printf("  [STATS] UTC=%d | requests=%d | matches=%d | map_size=%d\n",
				generator.CurrentUTCSecond(), total, match, srv.mapSize)
		}
	}()

	// Raw UDP listener — bypass miekg/dns server entirely
	_ = strings.ToLower // keep import
	conn, err := net.ListenPacket("udp4", *listenAddr)
	if err != nil {
		log.Fatalf("[FATAL] Cannot listen on %s: %v", *listenAddr, err)
	}
	defer conn.Close()

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		fmt.Println("\n  Shutting down server...")
		conn.Close()
	}()

	fmt.Printf("\n  ✓ Raw UDP DNS server listening on %s\n\n", *listenAddr)

	buf := make([]byte, 4096)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if strings.Contains(err.Error(), "use of closed") {
				break
			}
			log.Printf("[ERROR] ReadFrom: %v", err)
			continue
		}

		// Handle each packet in a goroutine
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go srv.handlePacket(conn, addr, pkt)
	}
}
