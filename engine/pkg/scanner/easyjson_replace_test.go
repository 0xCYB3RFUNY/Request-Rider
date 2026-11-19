package scanner

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestNucleiAndMailruRemoved verifies that neither github.com/projectdiscovery/nuclei/v3
// nor github.com/mailru/easyjson are present anywhere in the Go module dependency tree.
func TestNucleiAndMailruRemoved(t *testing.T) {
	cmd := exec.Command("go", "list", "-m", "all")
	cmd.Dir = "../.."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -m all failed: %v\nOutput: %s", err, string(out))
	}
	output := string(out)

	if strings.Contains(output, "github.com/projectdiscovery/nuclei/v3") {
		t.Fatalf("github.com/projectdiscovery/nuclei/v3 is still present in dependencies:\n%s", output)
	}

	if strings.Contains(output, "github.com/mailru/easyjson") {
		t.Fatalf("github.com/mailru/easyjson is still present in dependencies:\n%s", output)
	}

	t.Logf("PASS: Nuclei and Mail.ru are completely absent from go.mod dependency graph.")
}

// TestDockerAndScriptsSyncWithGoMod verifies that engine/Dockerfile, engine/.dockerignore,
// docker-stand.sh, run-engine.sh, and start.sh build strictly from the project's actual
// dependencies (engine/go.mod) and never fetch or install removed packages (such as
// github.com/projectdiscovery/nuclei/v3 or hardcoded external tool versions).
func TestDockerAndScriptsSyncWithGoMod(t *testing.T) {
	repoRoot := filepath.Clean("../../..")

	filesToCheck := []string{
		filepath.Join(repoRoot, "engine", "Dockerfile"),
		filepath.Join(repoRoot, "docker-stand.sh"),
		filepath.Join(repoRoot, "run-engine.sh"),
		filepath.Join(repoRoot, "start.sh"),
	}

	forbiddenSubstrings := []string{
		"github.com/projectdiscovery/nuclei",
		"github.com/mailru/easyjson",
		"NUCLEI_VERSION",
		"AS nuclei",
		"COPY --from=nuclei",
		"HTTPX_VERSION=",
	}

	for _, file := range filesToCheck {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("failed to read %s: %v", file, err)
		}
		content := string(raw)
		for _, forbidden := range forbiddenSubstrings {
			if strings.Contains(content, forbidden) {
				t.Errorf("%s still references removed or hardcoded dependency %q; Docker and scripts must build strictly from engine/go.mod", file, forbidden)
			}
		}
	}

	dockerfileRaw, err := os.ReadFile(filepath.Join(repoRoot, "engine", "Dockerfile"))
	if err != nil {
		t.Fatalf("failed to read engine/Dockerfile: %v", err)
	}
	dockerfile := string(dockerfileRaw)
	if !strings.Contains(dockerfile, "go build -trimpath -ldflags='-s -w' -o /httpx github.com/projectdiscovery/httpx/cmd/httpx") {
		t.Errorf("engine/Dockerfile must build /httpx directly from engine/go.mod inside the build stage")
	}

	dockerignoreRaw, err := os.ReadFile(filepath.Join(repoRoot, "engine", ".dockerignore"))
	if err != nil {
		t.Fatalf("failed to read engine/.dockerignore: %v", err)
	}
	dockerignore := string(dockerignoreRaw)
	for _, requiredIgnore := range []string{"/engine", "/jsanalyse", "*.sw*"} {
		if !strings.Contains(dockerignore, requiredIgnore) {
			t.Errorf("engine/.dockerignore is missing %q ignore rule", requiredIgnore)
		}
	}
}

// TestPassiveOperatorsNativeEvaluation verifies native operators and DSL evaluation without Nuclei.
func TestPassiveOperatorsNativeEvaluation(t *testing.T) {
	data := map[string]interface{}{
		"status_code": 200,
		"body":        "Admin Login Panel",
		"server":      "nginx/1.24.0",
	}

	// 1. DSL Expression test
	dslExpr := "status_code == 200 && contains(to_lower(body), 'admin login')"
	if !evalDSLExpression(dslExpr, data) {
		t.Fatalf("evalDSLExpression failed for valid expression %q", dslExpr)
	}

	// 2. DSL False condition
	dslFalse := "status_code == 404 || contains(body, 'Error')"
	if evalDSLExpression(dslFalse, data) {
		t.Fatalf("evalDSLExpression returned true for false expression %q", dslFalse)
	}

	// 3. DSL Expression with comparison symbols (<, >, ==) inside string literals of function calls
	dataWithHTML := map[string]interface{}{
		"status_code": 200,
		"body":        "<html><h1>Admin>Login</h1><p>a==b</p></html>",
	}
	dslHTML := `status_code == 200 && contains(body, "<h1>Admin>Login</h1>") && contains(body, "a==b")`
	if !evalDSLExpression(dslHTML, dataWithHTML) {
		t.Fatalf("evalDSLExpression failed when comparison symbols (<, >, ==) appear inside quoted arguments: %q", dslHTML)
	}

	// 4. Matcher Words test
	m := &Matcher{
		Type:      MatcherTypeHolder{MatcherType: WordsMatcher},
		Words:     []string{"Admin", "Login"},
		Condition: "and",
	}
	matched, snippets := m.MatchWords("Admin Login Panel", data)
	if !matched || len(snippets) != 2 {
		t.Fatalf("MatchWords AND failed: matched=%v snippets=%v", matched, snippets)
	}
}
