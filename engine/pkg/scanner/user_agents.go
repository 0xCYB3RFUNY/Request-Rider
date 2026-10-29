package scanner

import (
	"bufio"
	"crypto/rand"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	builtInUserAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:123.0) Gecko/20100101 Firefox/123.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
		"Mozilla/5.0 (Windows NT 6.4; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2225.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.2; rv:21.0) Gecko/20130326 Firefox/21.0",
		"Mozilla/5.0 (Windows NT 6.0; WOW64; rv:24.0) Gecko/20100101 Firefox/24.0",
		"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.93 Safari/537.36",
		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:17.0) Gecko/20100101 Firefox/17.0.6",
		"Mozilla/5.0 (Windows NT 6.2; rv:22.0) Gecko/20130405 Firefox/22.0",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:29.0) Gecko/20120101 Firefox/29.0",
	}

	uaPoolMu sync.RWMutex
	uaPool   []string
)

func init() {
	loadUserAgentsFromFiles()
}

func loadUserAgentsFromFiles() {
	uaPoolMu.Lock()
	defer uaPoolMu.Unlock()

	candidates := []string{
		"UserAgent.txt",
		"../UserAgent.txt",
		"../../UserAgent.txt",
		"../../../UserAgent.txt",
		"/home/kali/Desktop/DevBackUp-20.10/UserAgent.txt",
	}

	for _, p := range candidates {
		if abs, err := filepath.Abs(p); err == nil {
			if f, err := os.Open(abs); err == nil {
				defer f.Close()
				var loaded []string
				scanner := bufio.NewScanner(f)
				for scanner.Scan() {
					line := strings.TrimSpace(scanner.Text())
					if line != "" && !strings.HasPrefix(line, "#") {
						loaded = append(loaded, line)
					}
				}
				if len(loaded) > 0 {
					uaPool = loaded
					return
				}
			}
		}
	}

	uaPool = append([]string(nil), builtInUserAgents...)
}

// RandomUserAgent returns a realistic browser User-Agent from the anti-detect pool.
// It never returns any identifier containing "RequestRider" or "Request-Rider".
func RandomUserAgent() string {
	uaPoolMu.RLock()
	pool := uaPool
	if len(pool) == 0 {
		pool = builtInUserAgents
	}
	uaPoolMu.RUnlock()

	if len(pool) == 0 {
		return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
	}

	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(len(pool))))
	if err != nil {
		return pool[0]
	}
	return pool[nBig.Int64()]
}
