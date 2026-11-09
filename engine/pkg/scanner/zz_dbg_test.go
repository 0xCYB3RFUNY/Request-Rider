package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestZZDbg(t *testing.T) {
	root := "/home/kali/Desktop/nuclei-templates"
	var files []string
	_ = filepath.Walk(root, func(p string, i os.FileInfo, e error) error {
		if e == nil && !i.IsDir() && (strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml")) {
			files = append(files, p)
		}
		return nil
	})
	n := 0
	for _, p := range files {
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		d, _ := parsePassiveDocument(string(raw))
		if d == nil || strings.TrimSpace(d.Flow) == "" {
			continue
		}
		if _, e := parseFlow(d.Flow); e == nil {
			continue
		}
		n++
		f := strings.TrimSpace(d.Flow)
		if len(f) > 300 {
			f = f[:300]
		}
		fmt.Printf("### %s\n%s\n", strings.TrimPrefix(p, root+"/"), strings.ReplaceAll(f, "\n", " ⏎ "))
	}
	fmt.Printf("ЗАЛИШКІВ: %d\n", n)
}
