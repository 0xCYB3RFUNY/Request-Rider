package main

// Finds which single template makes the band allocate the most. The chunked
// measurement showed a 494 MB peak inside a chunk of 1000 while the live heap
// sat at 12 MB, so the cost is one template, not the corpus — and a memory
// number without a named cause is not actionable.

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"intruder/engine/pkg/scanner"
)

type reading struct {
	path  string
	bytes int
	heap  uint64
}

func main() {
	root := "/home/kali/.local/nuclei-templates"
	paths := corpusFiles(root)
	exchange := scanner.PassiveExchange{
		Method: "GET", URL: "https://shop.example.com/", Host: "https://shop.example.com",
		RawRequest:  "GET / HTTP/1.1\r\nHost: shop.example.com\r\n\r\n",
		RawResponse: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nhello",
		StatusCode:  200, Body: "hello",
		Header:        http.Header{"Content-Type": {"text/html"}},
		Duration:      10 * time.Millisecond,
		ContentLength: 5,
	}
	readings := make([]reading, 0, 64)
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	for _, path := range paths {
		payload, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		runtime.GC()
		var start runtime.MemStats
		runtime.ReadMemStats(&start)
		scanner.ScorePassiveTemplate(string(payload), exchange)
		runtime.GC()
		var end runtime.MemStats
		runtime.ReadMemStats(&end)
		retained := uint64(0)
		if end.HeapAlloc > start.HeapAlloc {
			retained = end.HeapAlloc - start.HeapAlloc
		}
		readings = append(readings, reading{path: path, bytes: len(payload), heap: retained})
	}
	sort.Slice(readings, func(i, j int) bool { return readings[i].heap > readings[j].heap })
	fmt.Println("top templates by retained heap after scoring:")
	for index, item := range readings {
		if index >= 10 {
			break
		}
		fmt.Printf("  %8.1f KB retained  %7d B file  %s\n",
			float64(item.heap)/1024, item.bytes, item.path)
	}
	sort.Slice(readings, func(i, j int) bool { return readings[i].bytes > readings[j].bytes })
	fmt.Println("\nlargest templates by file size:")
	for index, item := range readings {
		if index >= 5 {
			break
		}
		fmt.Printf("  %7d B file  %8.1f KB retained  %s\n", item.bytes, float64(item.heap)/1024, item.path)
	}
}

func corpusFiles(root string) []string {
	skip := map[string]bool{".git": true, ".github": true, "node_modules": true}
	var paths []string
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if skip[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
			paths = append(paths, path)
		}
		return nil
	})
	sort.Strings(paths)
	return paths
}
