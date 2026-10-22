package scanner

import (
	"testing"
)

// `-timeout` вище межі, яка зупинить цей виклик, не може дати вердикт.
//
// Виміряно на v3.11.1: вартість шаблону, чий запит не завершується, дорівнює
// `timeout × кількість запитів`, лінійно.
//
//	-timeout 5     16 с   1 запис
//	-timeout 12    37 с   1 запис
//	-timeout 20   >60 с   0 записів
//	-timeout 86400 не завершується
//
// Тому значення за замовчуванням у 86 400 секунд не було «безпечно великим» — воно
// було недостижним: межа батчу за замовчуванням 3 600 с, тож запит міг скінчитися
// лише як «зупинено на 3600-секундній межі».
//
// Інваріант, який тут закріплюється: межа запиту не перевищує межу, що зупинить
// виклик. Вона не про швидкість — вона про те, що вердикт у принципі можливий.

// 2026-10-07. Другий край того самого інваріанта, виміряний на `http/cves`
// (4356 документів) проти локальної вразливої цілі: прапорець, який ми передавали
// самому бінарнику, був **межею прогону**, тобто «годину на одне читання». Наслідок
// видно оператору як «скан дійшов до 70 % і завмер»:
//
//	nuclei з власним дефолтом (без -timeout)   вийшов, rc=0, 39 с, 4345 записів, 137 збігів
//	-timeout 3600 (те, що передавали ми)       не вийшов за 300 с
//
// Дамп горутин (SIGQUIT) показує причину: головна горутина стоїть у
// `core.(*WorkPool).Wait`, тобто `percent 100` у бінарника — це «відправлено», а не
// «завершено»; один вортер читає тіло відповіді, яке не закінчується, а інші чекають
// у `net/http.(*Transport).getConn` на з'єднання, яке він тримає.
//
// Тому межа прогону більше не стає бюджетом одного читання: вона завжди була питанням
// про весь прогін, і її виконує Go — контекстом, з яким запущено виклик. Сама межа
// прогону лишається видимою у звіті, у `stats.timeout_sec`.
func TestTheRunDeadlineIsNotHandedToTheBinaryAsAReadBudget(t *testing.T) {
	t.Setenv("RR_NUCLEI_PAUSABLE_TIMEOUT_SECONDS", "")
	t.Setenv("RR_NUCLEI_EXEC_TIMEOUT_MS", "")
	t.Setenv("RR_NUCLEI_TIMEOUT_SEC", "")

	args, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{
		deadlineSec: 3600,
	})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	if hasArg(args, "-timeout") {
		t.Fatalf("the run deadline reached the binary as a per-read budget (-timeout %q): "+
			"one slow document then holds a worker for the whole run, and the run never ends: %v",
			argValue(t, args, "-timeout"), args)
	}
}

// Явна межа прогону — це вже прохання саме по собі, тоді вона лишається обрізаною до
// себе: вище неї виклик усе одно завершено.
func TestAnExplicitlyWrittenRunDeadlineStillClampsTheReadBudget(t *testing.T) {
	t.Setenv("RR_NUCLEI_PAUSABLE_TIMEOUT_SECONDS", "")
	t.Setenv("RR_NUCLEI_TIMEOUT_SEC", "120")

	if got := pausableRequestTimeoutSeconds(120); got != 120 {
		t.Fatalf("pausableRequestTimeoutSeconds(120) = %d, want the written-down 120", got)
	}
	if got := pausableRequestTimeoutSeconds(3600); got != 120 {
		t.Fatalf("pausableRequestTimeoutSeconds(3600) = %d, want it clamped to the written 120", got)
	}
}

// Вибрана оператором величина — це рішення, а не дефолт, тому вона не обрізається:
// обрізання змінювало б те, що оператор попросив на власну відповідальність.
func TestAnOperatorValueIsTakenVerbatimEvenAboveTheDeadline(t *testing.T) {
	t.Setenv("RR_NUCLEI_PAUSABLE_TIMEOUT_SECONDS", "90000")
	t.Setenv("RR_NUCLEI_TIMEOUT_SEC", "")

	if got := pausableRequestTimeoutSeconds(120); got != 90000 {
		t.Fatalf("pausableRequestTimeoutSeconds(120) = %d, want the operator's 90000", got)
	}
	args, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{
		deadlineSec: 120,
	})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	if value := argValue(t, args, "-timeout"); value != "90000" {
		t.Fatalf("-timeout = %q, want the operator's value: %v", value, args)
	}
}

// `RR_NUCLEI_EXEC_TIMEOUT_MS` — окремий регулятор, і він має лишатись вище за межу
// батчу: оператор, який свідомо поставив межу запиту, прийняв наслідок.
func TestTheExplicitRequestTimeoutIsNotClamped(t *testing.T) {
	t.Setenv("RR_NUCLEI_PAUSABLE_TIMEOUT_SECONDS", "")
	t.Setenv("RR_NUCLEI_EXEC_TIMEOUT_MS", "600000") // 600 s
	t.Setenv("RR_NUCLEI_TIMEOUT_SEC", "")

	args, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{
		deadlineSec: 120,
	})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	if value := argValue(t, args, "-timeout"); value != "600" {
		t.Fatalf("-timeout = %q, want the explicit 600: %v", value, args)
	}
}

// Без батчу межа невідома, і тоді діє загальна межа прогону — але тільки коли
// оператор її написав. Мовчазливий дефолт не є проханням: саме він і тримав прогін.
func TestWithoutABatchTheWrittenRunBoundApplies(t *testing.T) {
	t.Setenv("RR_NUCLEI_PAUSABLE_TIMEOUT_SECONDS", "")
	t.Setenv("RR_NUCLEI_TIMEOUT_SEC", "900")

	if got := pausableRequestTimeoutSeconds(0); got != 900 {
		t.Fatalf("pausableRequestTimeoutSeconds(0) = %d, want the written run's 900", got)
	}
}

// Межа запиту не з'являється там, де пауза неможлива: тоді бібліотека не має
// жодного підставання піднімати її, і аргумент лише плутає оператора.
func TestNoRequestDeadlineWithoutPauseSupport(t *testing.T) {
	if pauseSupported() {
		t.Skip("this build can pause, so -timeout belongs in the invocation")
	}
	args, err := buildNucleiArgs("http://target.test/", "/tmp/staged", NucleiRequest{deadlineSec: 120})
	if err != nil {
		t.Fatalf("build args: %v", err)
	}
	if hasArg(args, "-timeout") {
		t.Fatalf("a build without pause support still got -timeout: %v", args)
	}
}

// Межа прогону має лишатися видимою у звіті прогону, і тепер вона читається саме
// звідти: `stats.timeout_sec`. Аргументи більше не несуть її дублем, але звіт — так.
func TestTheRunDeadlineStaysVisibleInTheRunStatistics(t *testing.T) {
	t.Setenv("RR_NUCLEI_PAUSABLE_TIMEOUT_SECONDS", "")
	t.Setenv("RR_NUCLEI_TIMEOUT_SEC", "3600")

	if got := nucleiTimeoutSec(); got != 3600 {
		t.Fatalf("nucleiTimeoutSec() = %d, want the written-down 3600 the report must show", got)
	}
	stats := runStatistics(&NucleiPlan{}, nil, "http://target.test/", nil)
	if value, _ := stats["timeout_sec"].(int); value != 3600 {
		t.Fatalf("stats.timeout_sec = %v, want 3600: a limit the operator cannot read is a hidden limit", stats["timeout_sec"])
	}
}

func joinArgs(args []string) string {
	out := ""
	for index, arg := range args {
		if index > 0 {
			out += " "
		}
		out += arg
	}
	return out
}

func containsArgText(joined, needle string) bool {
	for index := 0; index+len(needle) <= len(joined); index++ {
		if joined[index:index+len(needle)] == needle {
			return true
		}
	}
	return false
}
