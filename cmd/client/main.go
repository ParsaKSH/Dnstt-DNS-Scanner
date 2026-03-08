package main

import (
	"bufio"
	"context"
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

// cc
func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func writeLines(path string, lines []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	return w.Flush()
}

// queryDNS sends a DNS A query and returns the first A record IP, or nil on failure.
func queryDNS(resolver, fqdn string, timeout time.Duration) net.IP {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(fqdn), dns.TypeA)
	msg.RecursionDesired = true

	client := &dns.Client{
		Timeout: timeout,
		Net:     "udp",
	}

	resp, _, err := client.Exchange(msg, net.JoinHostPort(resolver, "53"))
	if err != nil || resp == nil {
		return nil
	}

	for _, ans := range resp.Answer {
		if a, ok := ans.(*dns.A); ok {
			return a.A.To4()
		}
	}
	return nil
}

// --- Phase 1: Liveness Check ---

func runLivenessPhase(ctx context.Context, cfg config.Config, resolvers []string) []string {
	timeout := time.Duration(cfg.TimeoutMs) * time.Millisecond
	var passed []string
	var mu sync.Mutex
	var checked int64
	total := int64(len(resolvers))

	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup

	// Progress ticker
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				c := atomic.LoadInt64(&checked)
				mu.Lock()
				w := len(passed)
				mu.Unlock()
				fmt.Printf("\r  [Phase 1] %d/%d checked | %d alive", c, total, w)
			case <-done:
				return
			}
		}
	}()

	subsPerSec := generator.SubdomainsPerSecond(cfg.Concurrency, cfg.QueryPerSec)

	for i, resolver := range resolvers {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, resolver string) {
			defer wg.Done()
			defer func() { <-sem }()

			utcSec := generator.CurrentUTCSecond()
			subIdx := idx % subsPerSec
			sub := generator.GenerateSubdomain(cfg.Seed, utcSec, subIdx, cfg.LabelCount, cfg.LabelLength)
			expectedIP := generator.GenerateResponseIP(cfg.Seed, utcSec, subIdx)
			fqdn := generator.FQDN(sub, cfg.Domain)

			actualIP := queryDNS(resolver, fqdn, timeout)
			if actualIP != nil && actualIP.Equal(expectedIP) {
				mu.Lock()
				passed = append(passed, resolver)
				mu.Unlock()
			}
			atomic.AddInt64(&checked, 1)
		}(i, resolver)
	}

	wg.Wait()
	close(done)

	c := atomic.LoadInt64(&checked)
	mu.Lock()
	w := len(passed)
	mu.Unlock()
	fmt.Printf("\r  [Phase 1] %d/%d checked | %d alive\n", c, total, w)
	return passed
}

// --- Phases 2-5: Stress Tests ---

func runStressPhase(ctx context.Context, cfg config.Config, resolvers []string, phaseNum, duration int) []string {
	timeout := time.Duration(cfg.TimeoutMs) * time.Millisecond
	interval := time.Second / time.Duration(cfg.QueryPerSec)
	var allPassed []string

	totalResolvers := len(resolvers)
	totalBatches := (totalResolvers + cfg.Concurrency - 1) / cfg.Concurrency
	batchNum := 0

	for batchStart := 0; batchStart < totalResolvers; batchStart += cfg.Concurrency {
		if ctx.Err() != nil {
			break
		}

		batchEnd := batchStart + cfg.Concurrency
		if batchEnd > totalResolvers {
			batchEnd = totalResolvers
		}
		batch := resolvers[batchStart:batchEnd]
		batchSize := len(batch)
		batchNum++

		success := make([]int64, batchSize)
		total := make([]int64, batchSize)

		// Progress
		var queriesSent int64
		totalExpected := int64(batchSize) * int64(cfg.QueryPerSec) * int64(duration)

		done := make(chan struct{})
		go func() {
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					sent := atomic.LoadInt64(&queriesSent)
					pct := float64(0)
					if totalExpected > 0 {
						pct = float64(sent) / float64(totalExpected) * 100
					}
					fmt.Printf("\r  [Phase %d] Batch %d/%d | %d/%d queries (%.1f%%)",
						phaseNum, batchNum, totalBatches, sent, totalExpected, pct)
				case <-done:
					return
				}
			}
		}()

		// Run stress test for this batch
		var batchWg sync.WaitGroup
		for slot := 0; slot < batchSize; slot++ {
			batchWg.Add(1)
			go func(slot int) {
				defer batchWg.Done()

				var queryWg sync.WaitGroup

				for sec := 0; sec < duration; sec++ {
					if ctx.Err() != nil {
						break
					}

					secStart := time.Now()
					utcSec := time.Now().UTC().Unix()

					for q := 0; q < cfg.QueryPerSec; q++ {
						if ctx.Err() != nil {
							break
						}

						idx := slot*cfg.QueryPerSec + q
						sub := generator.GenerateSubdomain(cfg.Seed, utcSec, idx, cfg.LabelCount, cfg.LabelLength)
						expectedIP := generator.GenerateResponseIP(cfg.Seed, utcSec, idx)
						fqdn := generator.FQDN(sub, cfg.Domain)

						// Fire query async
						queryWg.Add(1)
						go func(resolver, fqdn string, expectedIP net.IP, slot int) {
							defer queryWg.Done()
							actualIP := queryDNS(resolver, fqdn, timeout)
							atomic.AddInt64(&total[slot], 1)
							if actualIP != nil && actualIP.Equal(expectedIP) {
								atomic.AddInt64(&success[slot], 1)
							}
						}(batch[slot], fqdn, expectedIP, slot)

						atomic.AddInt64(&queriesSent, 1)

						// Pace: wait until next query slot within the second
						if q < cfg.QueryPerSec-1 {
							expectedElapsed := time.Duration(q+1) * interval
							actualElapsed := time.Since(secStart)
							if wait := expectedElapsed - actualElapsed; wait > 0 {
								time.Sleep(wait)
							}
						}
					}

					// Wait for the rest of the second
					elapsed := time.Since(secStart)
					if wait := time.Second - elapsed; wait > 0 {
						time.Sleep(wait)
					}
				}

				// Wait for in-flight queries to complete
				queryWg.Wait()
			}(slot)
		}

		batchWg.Wait()
		close(done)

		sent := atomic.LoadInt64(&queriesSent)
		fmt.Printf("\r  [Phase %d] Batch %d/%d | %d/%d queries (100.0%%)\n",
			phaseNum, batchNum, totalBatches, sent, totalExpected)

		// Evaluate batch results
		for i, resolver := range batch {
			s := atomic.LoadInt64(&success[i])
			t := atomic.LoadInt64(&total[i])
			pct := float64(0)
			if t > 0 {
				pct = float64(s) / float64(t) * 100
			}
			status := "FAIL"
			if pct >= cfg.PassPercent {
				status = "PASS"
				allPassed = append(allPassed, resolver)
			}
			if batchSize <= 50 { // Print table for small batches
				fmt.Printf("    %-18s %5d/%-5d %5.1f%% %s\n", resolver, s, t, pct, status)
			}
		}
	}

	return allPassed
}

func main() {
	startTime := time.Now()

	cfg := config.LoadConfig()

	// Setup SIGINT/SIGTERM handling
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Read resolver list
	resolvers, err := readLines(cfg.ListFile)
	if err != nil {
		log.Fatalf("[FATAL] Cannot read resolver list %s: %v", cfg.ListFile, err)
	}
	if len(resolvers) == 0 {
		log.Fatal("[FATAL] Resolver list is empty")
	}

	fmt.Println("┌──────────────────────────────────────────────────┐")
	fmt.Println("│       Dnstt DNS Scanner - Client v2.0            │")
	fmt.Println("└──────────────────────────────────────────────────┘")
	fmt.Printf("  Domain      : %s\n", cfg.Domain)
	fmt.Printf("  Seed        : %s\n", cfg.Seed)
	fmt.Printf("  Resolvers   : %d\n", len(resolvers))
	fmt.Printf("  Concurrency : %d\n", cfg.Concurrency)
	fmt.Printf("  QPS/resolver: %d\n", cfg.QueryPerSec)
	fmt.Printf("  Timeout     : %dms\n", cfg.TimeoutMs)
	fmt.Printf("  Pass %%      : %.1f%%\n", cfg.PassPercent)
	fmt.Printf("  Phases      : 1 (liveness) + %d (stress)\n", len(cfg.PhaseDurations))
	fmt.Printf("  UTC Time    : %s\n", time.Now().UTC().Format(time.RFC3339))

	// ═══ Phase 1: Liveness ═══
	fmt.Println("\n╔══════════════════════════════════════════════════╗")
	fmt.Println("║          PHASE 1: Liveness Check                 ║")
	fmt.Println("╚══════════════════════════════════════════════════╝")

	resolvers = runLivenessPhase(ctx, cfg, resolvers)
	if err := writeLines("phase1_output.txt", resolvers); err != nil {
		log.Printf("[ERROR] Cannot write phase1_output.txt: %v", err)
	}
	fmt.Printf("  ✓ %d resolvers alive. Saved to phase1_output.txt\n", len(resolvers))

	if ctx.Err() != nil || len(resolvers) == 0 {
		if len(resolvers) == 0 {
			fmt.Println("\n  [!] No alive resolvers found. Exiting.")
		}
		printElapsed(startTime)
		return
	}

	// ═══ Phases 2-5: Stress Tests ═══
	for i, duration := range cfg.PhaseDurations {
		if ctx.Err() != nil {
			break
		}
		if len(resolvers) == 0 {
			fmt.Println("\n  [!] No resolvers remaining. Exiting.")
			break
		}

		phaseNum := i + 2

		fmt.Printf("\n╔══════════════════════════════════════════════════╗\n")
		fmt.Printf("║          PHASE %d: Stress Test (%ds)              ║\n", phaseNum, duration)
		fmt.Printf("╚══════════════════════════════════════════════════╝\n")
		fmt.Printf("  Resolvers   : %d\n", len(resolvers))
		fmt.Printf("  Duration    : %ds\n\n", duration)

		resolvers = runStressPhase(ctx, cfg, resolvers, phaseNum, duration)

		// Determine output filename
		isLastPhase := i == len(cfg.PhaseDurations)-1
		var outFile string
		if isLastPhase {
			outFile = cfg.OutputFile
		} else {
			outFile = fmt.Sprintf("phase%d_output.txt", phaseNum)
		}

		if err := writeLines(outFile, resolvers); err != nil {
			log.Printf("[ERROR] Cannot write %s: %v", outFile, err)
		}
		fmt.Printf("\n  ✓ %d resolvers passed (≥%.1f%%). Saved to %s\n",
			len(resolvers), cfg.PassPercent, outFile)
	}

	printElapsed(startTime)
}

func printElapsed(startTime time.Time) {
	elapsed := time.Since(startTime)
	fmt.Printf("\n  Total time: %s\n", elapsed.Round(time.Millisecond))
	fmt.Println("  Done!")
}
