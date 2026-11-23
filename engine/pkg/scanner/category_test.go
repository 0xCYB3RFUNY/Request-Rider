package scanner

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestFilterStagedTemplatesByCategorySelectsOnlyDescendants(t *testing.T) {
	staged := []StagedFile{
		{RelativePath: "templates/code/check.yaml"},
		{RelativePath: "templates/code/nested/second.yaml"},
		{RelativePath: "templates/code/helpers/words.txt", Support: true},
		{RelativePath: "templates/codex/unrelated.yaml"},
		{RelativePath: "templates/dast/check.yaml"},
	}

	got, err := filterStagedTemplatesByCategory(staged, "templates/code")
	if err != nil {
		t.Fatalf("filter category: %v", err)
	}
	want := []StagedFile{staged[0], staged[1]}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("filtered templates = %#v, want %#v", got, want)
	}
}

func TestFilterStagedTemplatesByCategoryKeepsAllForExplicitEmptySelection(t *testing.T) {
	staged := []StagedFile{
		{RelativePath: "one.yaml"},
		{RelativePath: "helpers/words.txt", Support: true},
		{RelativePath: "two.yaml"},
	}

	got, err := filterStagedTemplatesByCategory(staged, "")
	if err != nil {
		t.Fatalf("empty category: %v", err)
	}
	want := []StagedFile{staged[0], staged[2]}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("empty category returned %#v, want all templates but no helper rows", got)
	}
}

func TestFilterStagedTemplatesByCategoryRejectsInvalidOrEmptyPaths(t *testing.T) {
	staged := []StagedFile{{RelativePath: "templates/code/check.yaml"}}
	for _, category := range []string{"/templates/code", "../code", "templates/../code", "."} {
		t.Run(category, func(t *testing.T) {
			if _, err := filterStagedTemplatesByCategory(staged, category); err == nil {
				t.Fatalf("category %q was accepted", category)
			}
		})
	}
	if _, err := filterStagedTemplatesByCategory(staged, "templates/missing"); err == nil {
		t.Fatal("a category with no staged templates was accepted")
	}
}

func TestRunNucleiDirRunsOnlyTheSelectedCategory(t *testing.T) {
	stub := filepath.Join(t.TempDir(), "nuclei-category-stub.sh")
	script := "#!/bin/sh\n" +
		"out=''\ntemplates=''\nprev=''\n" +
		"for arg in \"$@\"; do\n" +
		"  if [ \"$prev\" = '-o' ]; then out=\"$arg\"; fi\n" +
		"  if [ \"$prev\" = '-t' ]; then templates=\"$arg\"; fi\n" +
		"  prev=\"$arg\"\n" +
		"done\n" +
		": > \"$out\"\n" +
		"for f in $(find \"$templates\" -name '*.yaml' | sort); do\n" +
		"  id=$(sed -n 's/^id:[[:space:]]*//p' \"$f\" | head -1)\n" +
		"  printf '%s\\n' \"{\\\"template-id\\\":\\\"$id\\\",\\\"template-path\\\":\\\"$f\\\",\\\"matcher-status\\\":false}\" >> \"$out\"\n" +
		"done\n"
	if err := os.WriteFile(stub, []byte(script), 0o700); err != nil {
		t.Fatalf("write nuclei stub: %v", err)
	}
	t.Setenv("RR_NUCLEI_BINARY", stub)

	dir, staged, err := StageUploads([]UploadFile{
		{Name: "first.yaml", Path: "templates/code/first.yaml", Content: idTemplateAt("code-first", "/first")},
		{Name: "nested.yaml", Path: "templates/code/nested/nested.yaml", Content: idTemplateAt("code-nested", "/nested")},
		{Name: "other.yaml", Path: "templates/http/other.yaml", Content: idTemplateAt("http-other", "/other")},
	})
	if err != nil {
		t.Fatalf("stage templates: %v", err)
	}
	defer os.RemoveAll(dir)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	run, err := RunNucleiDir(ctx, dir, staged, NucleiRequest{
		URL:          "http://target.test/",
		CategoryPath: "templates/code",
	})
	if err != nil {
		t.Fatalf("run selected category: %v", err)
	}
	if len(run.Templates) != 2 {
		t.Fatalf("reported %d templates, want only the two selected-category files: %+v", len(run.Templates), run.Templates)
	}
	var names []string
	for _, template := range run.Templates {
		names = append(names, template.Name)
	}
	sort.Strings(names)
	if got := strings.Join(names, ","); got != "first.yaml,nested.yaml" {
		t.Fatalf("reported templates %q, want first.yaml and nested.yaml", got)
	}
}
