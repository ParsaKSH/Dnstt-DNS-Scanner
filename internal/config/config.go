package config

import (
	"encoding/json"
	"flag"
	"log"
	"os"
)

// Config holds shared configuration for both client and server.
type Config struct {
	Seed           string  `json:"seed"`
	Domain         string  `json:"domain"`
	Concurrency    int     `json:"concurrency"`
	QueryPerSec    int     `json:"query_per_sec"`
	TimeoutMs      int     `json:"timeout_ms"`
	PassPercent    float64 `json:"pass_percent"`
	ListFile       string  `json:"list_file"`
	OutputFile     string  `json:"output_file"`
	PhaseDurations []int   `json:"phase_durations"` // durations in seconds for phases 2-5
}

// DefaultConfig returns a config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Seed:           "default-seed",
		Domain:         "ns1.example.com",
		Concurrency:    10,
		QueryPerSec:    10,
		TimeoutMs:      4000,
		PassPercent:    80.0,
		ListFile:       "list.txt",
		OutputFile:     "output.txt",
		PhaseDurations: []int{2, 4, 8, 16},
	}
}

// LoadConfig loads configuration from a JSON file with CLI flag overrides.
func LoadConfig() Config {
	cfg := DefaultConfig()

	configPath := flag.String("config", "config.json", "Path to config.json")
	seed := flag.String("seed", "", "Shared seed for generation")
	domain := flag.String("domain", "", "NS domain")
	concurrency := flag.Int("concurrency", 0, "Number of concurrent resolvers")
	qps := flag.Int("qps", 0, "Queries per second per resolver")
	timeoutMs := flag.Int("timeout", 0, "Query timeout in milliseconds")
	passPercent := flag.Float64("pass-percent", 0, "Minimum pass percentage")
	listFile := flag.String("list", "", "Path to resolver list file")
	outputFile := flag.String("output", "", "Path to final output file")
	flag.Parse()

	// Load from JSON file
	if data, err := os.ReadFile(*configPath); err == nil {
		if err := json.Unmarshal(data, &cfg); err != nil {
			log.Printf("[WARN] Failed to parse %s: %v", *configPath, err)
		} else {
			log.Printf("[INFO] Loaded config from %s", *configPath)
		}
	}

	// CLI flags override JSON config
	if *seed != "" {
		cfg.Seed = *seed
	}
	if *domain != "" {
		cfg.Domain = *domain
	}
	if *concurrency > 0 {
		cfg.Concurrency = *concurrency
	}
	if *qps > 0 {
		cfg.QueryPerSec = *qps
	}
	if *timeoutMs > 0 {
		cfg.TimeoutMs = *timeoutMs
	}
	if *passPercent > 0 {
		cfg.PassPercent = *passPercent
	}
	if *listFile != "" {
		cfg.ListFile = *listFile
	}
	if *outputFile != "" {
		cfg.OutputFile = *outputFile
	}

	return cfg
}
