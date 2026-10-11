package main

// Механічна перевірка реєстру звірки з `projectdiscovery/tlsx`.
//
// Цей реєстр єдиний у наборі, який звіряється **не з клону**, а з модульного
// кешу Go. Причина практична: клони видалені з дерева, а `tlsx` — пряма
// залежність, тож його вихідники лежать у `$(go env GOMODCACHE)` і це той самий
// код, який компілюється в наш бінарник.
//
// Тому головна перевірка читає `CertificateResponse` з кешу і вимагає, щоб
// **кожне поле** типу було або назване в реєстрі, або мало рядок із вердиктом
// `не перенесено`. Реєстр без неї просто виміряє «20 полів» один раз, а
// upstream їх змінить — і цифра залишиться.
import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

const tlsxRegistry = "tlsx_reconciliation.md"

// tlsxVersion — версія з `go.mod`. Не вигадується: тест звіряє її з кешем, і
// якщо версія зміниться без зміни реєстру, перевірка впаде.
const tlsxVersion = "v1.3.2"

var tlsxUpstreamCommit = regexp.MustCompile(
	`Upstream-коміт, звірка проти якого зроблена: ` + "`" + `([0-9a-f]{7,40}|v[0-9]+\.[0-9]+\.[0-9]+)` + "`")

var tlsxVerdicts = map[string]bool{
	"супадає":       true,
	"улучшено":      true,
	"не перенесено": true,
}

var tlsxRow = regexp.MustCompile(`^\|\s*(\d+)\s*\|(.+)\|\s*$`)

// tlsxStructField — одне поле структури оригіналу.
var tlsxStructField = regexp.MustCompile(`^\s+([A-Z][A-Za-z0-9]*)\s+\S+\s+` + "`" + `json:"([a-z_]+)`)

const tlsxRequiredRows = 12

func readTlsxRegistry(t *testing.T) [][]string {
	t.Helper()
	raw, err := os.ReadFile(tlsxRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", tlsxRegistry, err)
	}
	rows := make([][]string, 0, tlsxRequiredRows)
	for _, line := range strings.Split(string(raw), "\n") {
		match := tlsxRow.FindStringSubmatch(strings.TrimSpace(line))
		if match == nil {
			continue
		}
		cells := strings.Split(match[2], "|")
		if len(cells) < 5 {
			continue
		}
		rows = append(rows, append([]string{match[1]}, cells...))
	}
	return rows
}

func tlsxCell(row []string, index int) string {
	if index >= len(row) {
		return ""
	}
	return strings.Trim(strings.TrimSpace(row[index]), "`")
}

// tlsxDir знаходить вихідники оригіналу в модульному кеші.
//
// Тут SKIP, а не FAIL: відсутність кешу — це відсутність джерела для звірки,
// а не помилка нашого коду. Мовчати не можна, тому що тоді числа реєстру
// перестають бути перевіреними нібито, і це має бути видно.
func tlsxDir(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "env", "GOMODCACHE").Output()
	if err != nil {
		t.Skipf("go env GOMODCACHE failed (%v): the registry's field list cannot be "+
			"verified against the original", err)
	}
	dir := filepath.Join(strings.TrimSpace(string(out)),
		"github.com/projectdiscovery/tlsx@"+tlsxVersion)
	if info, statErr := os.Stat(dir); statErr != nil || !info.IsDir() {
		t.Skipf("tlsx %s not found at %s: the registry's field list cannot be "+
			"verified against the original", tlsxVersion, dir)
	}
	return dir
}

func tlsxSources(t *testing.T) string {
	t.Helper()
	parts := []string{}
	for _, root := range []string{".", "pkg"} {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			parts = append(parts, string(raw))
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	if len(parts) == 0 {
		t.Fatalf("no sources were read: the check would pass on an empty tree")
	}
	return strings.Join(parts, "\n")
}

// TestTlsxRegistryFixesTheUpstreamCommit — предмет звірки зафіксовано.
func TestTlsxRegistryFixesTheUpstreamCommit(t *testing.T) {
	raw, err := os.ReadFile(tlsxRegistry)
	if err != nil {
		t.Fatalf("read %s: %v", tlsxRegistry, err)
	}
	if !tlsxUpstreamCommit.Match(raw) {
		t.Fatalf("%s does not record the upstream commit", tlsxRegistry)
	}
	if !strings.Contains(string(raw), tlsxVersion) {
		t.Errorf("%s does not mention the version %s that the module cache holds",
			tlsxRegistry, tlsxVersion)
	}
}

// TestTheTlsxRegistryHasEveryRowItPromises — число рядків не зменшується мовчки.
func TestTheTlsxRegistryHasEveryRowItPromises(t *testing.T) {
	if got := len(readTlsxRegistry(t)); got < tlsxRequiredRows {
		t.Errorf("%s has %d numbered rows, want at least %d", tlsxRegistry, got, tlsxRequiredRows)
	}
}

// TestEveryTlsxRowHasAVerdictFromTheThree — четвертого стану не існує.
func TestEveryTlsxRowHasAVerdictFromTheThree(t *testing.T) {
	for _, row := range readTlsxRegistry(t) {
		verdict := tlsxCell(row, 3)
		if verdict == "" {
			t.Errorf("row %s has no verdict cell", row[0])
			continue
		}
		if !tlsxVerdicts[verdict] {
			t.Errorf("row %s verdict %q is not one of супадає / улучшено / не перенесено",
				row[0], verdict)
		}
	}
}

// TestEveryNotPortedTlsxRowSaysWhy — причина обов'язкова.
func TestEveryNotPortedTlsxRowSaysWhy(t *testing.T) {
	for _, row := range readTlsxRegistry(t) {
		if tlsxCell(row, 3) != "не перенесено" {
			continue
		}
		tail := strings.Join(row[min(len(row), 5):], " | ")
		if strings.Trim(tail, " |") == "" {
			t.Errorf("row %s is не перенесено with no reason", row[0])
			continue
		}
		if !strings.Contains(strings.ToLower(tail), "причина") {
			t.Errorf("row %s is не перенесено but the reason never says why: %s", row[0], tail)
		}
	}
}

// TestEveryTlsxRowNamesASymbolThatExists — заявлений символ має бути в дереві.
func TestEveryTlsxRowNamesASymbolThatExists(t *testing.T) {
	sources := tlsxSources(t)
	for _, row := range readTlsxRegistry(t) {
		symbol := tlsxCell(row, len(row)-1)
		if symbol == "" || symbol == "—" || symbol == "-" {
			continue
		}
		if !strings.Contains(sources, symbol) {
			t.Errorf("row %s claims symbol %q, which is not in the tree", row[0], symbol)
		}
	}
}

// TestEveryCertificateFieldIsNamedOrDeclaredMissing — головна перевірка.
//
// `CertificateResponse` має 20 полів. Кожне має бути або назване в реєстрі, або
// отримати рядок із вердиктом `не перенесено`. Поле без рядка — це здатність,
// про яку ніхто не подумав; саме її реєстр має ловити, а не пам'ятати.
//
// Реєстр заявляє «10 з 20», і саме цю цифру перевірка й тримає: якщо ми додамо
// `revoked`, а вона вже є в реєстрі — все добре; якщо додамо поле в код і
// забудумо про реєстр — перевірка цього не побачить, але її побачить наступна
// зміна upstream.
func TestEveryCertificateFieldIsNamedOrDeclaredMissing(t *testing.T) {
	path := filepath.Join(tlsxDir(t), "pkg/tlsx/clients/clients.go")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read upstream CertificateResponse: %v", err)
	}

	registry, readErr := os.ReadFile(tlsxRegistry)
	if readErr != nil {
		t.Fatalf("read %s: %v", tlsxRegistry, readErr)
	}
	text := strings.ToLower(string(registry))

	fields := []string{}
	inStruct := false
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "type CertificateResponse struct") {
			inStruct = true
			continue
		}
		if inStruct && trimmed == "}" {
			break
		}
		if !inStruct {
			continue
		}
		if match := tlsxStructField.FindStringSubmatch(line); match != nil {
			fields = append(fields, match[2])
		}
	}
	if len(fields) == 0 {
		t.Fatalf("no fields parsed from the upstream CertificateResponse: the " +
			"check would pass on a type whose shape changed")
	}
	if len(fields) != 20 {
		t.Errorf("the upstream CertificateResponse holds %d fields, and the "+
			"registry's headline says 20: the original changed and the registry's "+
			"summary needs a look", len(fields))
	}

	missing := []string{}
	for _, field := range fields {
		if !strings.Contains(text, field) {
			missing = append(missing, field)
		}
	}
	for _, field := range missing {
		t.Errorf("upstream field %q has no registry row: a certificate field we "+
			"do not mention is a field we never thought about", field)
	}
}

// TestTheRegistryAdmitsTheWholeProbeCount — реєстр каже, скільки полів ми беремо.
//
// Ця перевірка існує через конкретну помилку першої редакції. Я виміряв
// `osint_http_probe.go` у діапазоні рядків 519-545, написав «10 з 20» — і це
// було вдвічі неправильно: `grep -oE '"tls_[a-z_]+"'` по всьому файлу дає
// **18**, бо вісім властивостей лежать **вище** того діапазону (їх читають з
// `record.TLSData`, а не з `leaf`).
//
// Тому тут рахується весь файл, без діапазонів. Діапазон — це вибірка, а
// вибірка завжди дає занижене число, схоже на правду, і тому її легко не
// помітити.
func TestTheRegistryAdmitsTheWholeProbeCount(t *testing.T) {
	raw, err := os.ReadFile("osint_http_probe.go")
	if err != nil {
		t.Fatalf("read our own probe: %v", err)
	}
	taken := map[string]bool{}
	for _, match := range regexp.MustCompile(`"(tls_[a-z0-9_]+)"`).
		FindAllStringSubmatch(string(raw), -1) {
		taken[match[1]] = true
	}
	if len(taken) == 0 {
		t.Fatalf("no tls_ properties found in our probe: the check would pass on " +
			"a file that stopped reading certificates")
	}
	if !taken["tls_expired"] {
		t.Errorf("our probe no longer reports tls_expired: the registry's row 1 " +
			"claims we take the basic certificate fields, and that is no longer true")
	}
	// Рядок 10 реєстру стверджує, що ми беремо jarm і ja3. Це перевіряється
	// окремо: саме тут перша редакція помилилася, написавши «не рахуємо».
	if !taken["tls_jarm"] || !taken["tls_ja3"] {
		t.Errorf("our probe reports jarm=%v ja3=%v, but the registry's row 10 "+
			"claims we take both handshake fingerprints",
			taken["tls_jarm"], taken["tls_ja3"])
	}

	// Число в реєстрі має збігатися з тим, що робить код. Якщо ми додамо
	// `revoked` і забудемо поправити реєстр — розходження стане видимим, а
	// не сховається за зеленим тестом.
	registry, readErr := os.ReadFile(tlsxRegistry)
	if readErr != nil {
		t.Fatalf("read %s: %v", tlsxRegistry, readErr)
	}
	claimed := tlsxClaimedCount(t, string(registry))
	if claimed == 0 {
		t.Fatalf("%s does not state how many fields we take: the number cannot "+
			"be checked against the code", tlsxRegistry)
	}
	if claimed != len(taken) {
		t.Errorf("the registry says we take %d fields, the probe actually reports "+
			"%d: %v", claimed, len(taken), tlsxSortedKeys(taken))
	}
}

// TestTheFingerprintRowAgreesWithTheProbe — вердикт рядка має збігатися з кодом.
//
// Ця перевірка з'явилася після того, як мутація реєстру (рядок 10 з `супадає`
// на `не перенесено`) **пройшла** зеленою. Причина реальна: попередні перевірки
// дивилися або на форму реєстру, або на код, але ніхто не порівнював вердикт
// конкретного рядка з тим, що код насправді робить.
//
// Тобто реєстр міг сказати «відбитки не беремо», а `osint_http_probe.go` міг
// далі їх писати — і все лишалося зеленим. Це той самий клас дефекту, що й
// реєстр без рядка: обидва випадки непомітні.
func TestTheFingerprintRowAgreesWithTheProbe(t *testing.T) {
	raw, err := os.ReadFile("osint_http_probe.go")
	if err != nil {
		t.Fatalf("read our own probe: %v", err)
	}
	probe := string(raw)
	taken := map[string]bool{}
	for _, match := range regexp.MustCompile(`"(tls_[a-z0-9_]+)"`).
		FindAllStringSubmatch(probe, -1) {
		taken[match[1]] = true
	}

	rows := readTlsxRegistry(t)
	found := 0
	for _, row := range rows {
		// Рядок про відбитки той, у якому згадано jarm у стовпці «здатність»
		// або «де в оригіналі». Інших such немає, тож збіг однозначний.
		line := strings.Join(row, " | ")
		if !strings.Contains(line, "jarm") {
			continue
		}
		found++
		verdict := tlsxCell(row, 3)
		switch {
		case taken["tls_jarm"] && verdict == "не перенесено":
			t.Errorf("row %s is не перенесено, but the probe writes tls_jarm at "+
				"osint_http_probe.go: the verdict contradicts the code", row[0])
		case taken["tls_ja3"] && verdict == "не перенесено":
			t.Errorf("row %s is не перенесено, but the probe writes tls_ja3 too: "+
				"the verdict contradicts the code", row[0])
		}
	}
	if found == 0 {
		t.Fatalf("no registry row mentions jarm, so this check cannot compare a " +
			"verdict against the code: the registry lost the row and the gap is " +
			"invisible")
	}
}

// tlsxClaimedCountLine дістає з реєстру підсумкове число властивостей `tls_`.
//
// Зіставка навмисно точна: у реєстрі кілька рядків «полів … ми беремо», і
// перший із них — про `CertificateResponse` (10), а не загальний (19). Взять
// «перший збіг» означало б звіряти тест із одним рядком таблиці, а не з тим,
// що реєстр твердить загалом.
var tlsxClaimedCountLine = regexp.MustCompile(
	"усього властивостей .tls_.[^|]*\\|\\s*\\*\\*(\\d+)\\*\\*")

func tlsxClaimedCount(t *testing.T, registry string) int {
	t.Helper()
	match := tlsxClaimedCountLine.FindStringSubmatch(registry)
	if match == nil {
		return 0
	}
	count := 0
	for _, digit := range match[1] {
		count = count*10 + int(digit-'0')
	}
	return count
}

func tlsxSortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
