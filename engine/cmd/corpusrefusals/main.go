package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"intruder/engine/pkg/scanner"
)

func main() {
	root := os.Args[1]
	var paths []string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		n := strings.ToLower(d.Name())
		if strings.HasSuffix(n, ".yaml") || strings.HasSuffix(n, ".yml") {
			paths = append(paths, path)
		}
		return nil
	})
	sort.Strings(paths)
	var reasons []string
	counts := map[string]int{}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		rel, _ := filepath.Rel(root, p)
		_, reason := scanner.ParseTemplateDocumentWithPath(string(b), filepath.ToSlash(rel))
		if reason != "" {
			key := reason
			if i := strings.Index(reason, " ("); i > 0 {
				key = reason[:i]
			}
			counts[key]++
			reasons = append(reasons, rel+"\t"+reason)
		}
	}
	fmt.Printf("files=%d refused=%d\n", len(paths), len(reasons))
	type kv struct {
		K string
		V int
	}
	var list []kv
	for k, v := range counts {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].V > list[j].V })
	for _, item := range list {
		fmt.Printf("  %6d  %s\n", item.V, item.K)
	}
	_ = os.WriteFile("/tmp/rr-ses-scr/all-refusals.tsv", []byte(strings.Join(reasons, "\n")+"\n"), 0o600)
}
