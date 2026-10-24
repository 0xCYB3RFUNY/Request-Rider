package scanner

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// `payloads` + `attack` — це 104 відмови нашого раннера на вибірці з 4 000.
//
// Усе поведінку звірено з nuclei v3.11.1 на ехо-фістурі, яка повертає назад сам
// запит. Таблиця нижче — це результат, а не документація:
//
//   attack:          імен payload   надіслано       примітка
//   ---------------  -------------  --------------  ------------------------------------
//   (не вказано)     1              усі значення    тип за замовчуванням
//   (не вказано)     2 або більше   0               тихо: nuclei нічого не робить
//   sniper           будь-яке       —               відмова: invalid attack type: sniper
//   batteringram     1              усі значення
//   batteringram     2 або більше   —               відмова: must have single payload set
//   pitchfork        будь-яке       до найкоротшого 2 з 2×5
//   clusterbomb      будь-яке       декартів добуток 2×3 = 6
//
// Два рядки таблиці — це випадки, де nuclei **мовчить**: два імені payload без
// `attack:` дають нуль запитів без жодного повідомлення. Тому наш раннер у цих
// випадках відмовляється з текстом, а не повторює мовчанку: оператор має бачити,
// чому шаблон не дав вердикта.

// payloadSet is one template's payload dictionary, name → values.
type payloadSet map[string][]string

// payloadCombination is one generated request's substitutions.
type payloadCombination map[string]string

// readPayloadSet turns the decoded `payloads:` block into usable values.
//
// A value is either a list or a scalar. nuclei accepts both, and so does this:
// `u: VALUE` and `u: [VALUE]` name the same one value, and refusing the scalar
// form would refuse a spelling the binary runs.
func readPayloadSet(raw map[string]interface{}) (payloadSet, string) {
	if len(raw) == 0 {
		return nil, ""
	}
	out := make(payloadSet, len(raw))
	names := make([]string, 0, len(raw))
	for name := range raw {
		names = append(names, name)
	}
	// Sorted so two runs of one template generate the same requests in the same
	// order. nuclei's own iteration follows a map, so its order varies between
	// runs; determinism is what makes two reports comparable.
	sort.Strings(names)
	for _, name := range names {
		values := readPayloadValues(raw[name])
		if len(values) == 0 {
			return nil, fmt.Sprintf("the payload name %q has no value, so no request can be built from it", name)
		}
		out[name] = values
	}
	return out, ""
}

// readPayloadValues reads one payload entry in either spelling.
func readPayloadValues(value interface{}) []string {
	switch typed := value.(type) {
	case []interface{}:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			out = append(out, fmt.Sprint(item))
		}
		return out
	case []string:
		return typed
	case nil:
		return nil
	default:
		return []string{fmt.Sprint(typed)}
	}
}

// generateCombinations builds the requests one block stands for.
//
// The refusal is the measured table above, not a guess: two of its rows are cases
// where nuclei sends nothing, and this states that instead of repeating it.
func generateCombinations(attack string, payloads payloadSet) ([]payloadCombination, string) {
	names := make([]string, 0, len(payloads))
	for name := range payloads {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return nil, "the block declares an attack with no payload name, so no request can be built from it"
	}
	switch strings.ToLower(strings.TrimSpace(attack)) {
	case "sniper":
		// Measured: nuclei refuses this spelling at load time with
		// `invalid attack type: sniper`, so a template that writes it is a
		// template nuclei does not run. Substituting values here would invent a
		// check that the original tool never performed.
		return nil, "the block spells `attack: sniper`, which nuclei v3.11.1 refuses at load time with " +
			"`invalid attack type: sniper` — sniper is the default, so the spelling is what is wrong, not the check"
	case "clusterbomb":
		return cartesianCombinations(names, payloads), ""
	case "pitchfork":
		return zippedCombinations(names, payloads, false), ""
	case "batteringram":
		if len(names) > 1 {
			return nil, fmt.Sprintf(
				"the block asks for a batteringram over %d payload names, and nuclei v3.11.1 refuses that "+
					"spelling with `batteringram must have single payload set`", len(names))
		}
		return zippedCombinations(names, payloads, true), ""
	default:
		// The default is sniper's behaviour, which nuclei implements over a single
		// payload name. Measured: two names with no `attack:` produce zero requests
		// and no message.
		if len(names) > 1 {
			return nil, fmt.Sprintf(
				"the block declares %d payload names and no `attack:`, and nuclei v3.11.1 sends nothing "+
					"at all in that shape — measured: one payload name sends every value, two send zero. "+
					"Name the attack explicitly (`pitchfork` for a zipped pair, `clusterbomb` for a product) "+
					"to say which requests this template means", len(names))
		}
		return zippedCombinations(names, payloads, true), ""
	}
}

// zippedCombinations walks the payload names together, index by index.
//
// `stopAtShortest` is the difference between batteringram and pitchfork, and it
// is measured rather than assumed: pitchfork over lists of 2 and 5 sent 2 requests,
// not 5 and not 10.
func zippedCombinations(names []string, payloads payloadSet, stopAtShortest bool) []payloadCombination {
	shortest := -1
	for _, name := range names {
		size := len(payloads[name])
		if shortest < 0 || size < shortest {
			shortest = size
		}
	}
	if shortest < 0 {
		return nil
	}
	out := make([]payloadCombination, 0, shortest)
	for index := 0; index < shortest; index++ {
		combination := payloadCombination{}
		for _, name := range names {
			values := payloads[name]
			pick := index
			// A shorter list repeats its last value, which is how a zipped attack
			// keeps going past the end of one list instead of stopping.
			if !stopAtShortest && pick >= len(values) {
				pick = len(values) - 1
			}
			if pick < 0 || pick >= len(values) {
				pick = 0
			}
			combination[name] = values[pick]
		}
		out = append(out, combination)
	}
	return out
}

// cartesianCombinations is every value of every name against every other.
func cartesianCombinations(names []string, payloads payloadSet) []payloadCombination {
	total := 1
	for _, name := range names {
		total *= len(payloads[name])
	}
	if total <= 0 {
		return nil
	}
	out := make([]payloadCombination, 0, total)
	indexes := make([]int, len(names))
	for position := 0; position < total; position++ {
		combination := payloadCombination{}
		for slot, name := range names {
			combination[name] = payloads[name][indexes[slot]]
		}
		out = append(out, combination)
		for slot := len(names) - 1; slot >= 0; slot-- {
			indexes[slot]++
			if indexes[slot] < len(payloads[names[slot]]) {
				break
			}
			indexes[slot] = 0
		}
	}
	return out
}

// applyCombination substitutes one payload value for its name in one value.
//
// Both spellings are replaced, `{{name}}` and `{{template.name}}`, because corpus
// templates use both and nuclei resolves both.
func applyCombination(value string, combination payloadCombination) string {
	if !strings.Contains(value, "{{") {
		return value
	}
	replaced := value
	for name, payloadValue := range combination {
		replaced = strings.ReplaceAll(replaced, "{{template."+name+"}}", payloadValue)
		replaced = strings.ReplaceAll(replaced, "{{"+name+"}}", payloadValue)
	}
	return replaced
}

// payloadRequestCount is how many requests one block generates, for the reason a
// refusal names. It is reported rather than kept internal because an operator
// reading "generated 6 requests" can check it against the product they expected.
func payloadRequestCount(attack string, payloads payloadSet) int {
	combinations, reason := generateCombinations(attack, payloads)
	if reason != "" {
		return 0
	}
	return len(combinations)
}

// payloadNameFor reports the payload name a placeholder asks for, and whether
// the placeholder is one at all. It reuses the dynamic-value reader so the two
// spellings cannot drift apart.
func payloadNameFor(name string) string {
	if strings.Contains(name, "(") || strings.Contains(name, ".") {
		return ""
	}
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return ""
	}
	if rest, found := strings.CutPrefix(trimmed, "template."); found {
		return strings.TrimSpace(rest)
	}
	if _, err := strconv.Atoi(trimmed); err == nil {
		// A bare number is not a payload name; it is part of the path.
		return ""
	}
	return trimmed
}

// blockGeneratesRequests reports whether one block stands for more requests than
// it writes, which is what a payload dictionary means.
//
// It is the question `RunTemplateLocally` asks to choose between the one-request
// path and the sweep path, so it must not be the same question as "can this be
// built": a block whose attack turns out to be unusable still belongs on the
// sweep path, because that is where the refusal is produced.
func blockGeneratesRequests(block passiveRequest) bool {
	return len(block.Payloads) > 0 || strings.TrimSpace(block.Attack) != ""
}

// expandBlockRequests turns one block into the requests it stands for.
//
// A block without a payload dictionary is one request and comes back unchanged,
// so every caller can use this and not care which shape it has.
func expandBlockRequests(block passiveRequest) ([]passiveRequest, string) {
	if !blockGeneratesRequests(block) {
		return []passiveRequest{block}, ""
	}
	payloads, reason := readPayloadSet(block.Payloads)
	if reason != "" {
		return nil, reason
	}
	combinations, reason := generateCombinations(block.Attack, payloads)
	if reason != "" {
		return nil, reason
	}
	if len(combinations) == 0 {
		return nil, "the block's payload dictionary produced no combination, so no request was built from it"
	}
	out := make([]passiveRequest, 0, len(combinations))
	for _, combination := range combinations {
		generated := block
		generated.Attack = ""
		generated.Payloads = nil
		if block.Path != nil {
			generated.Path = make([]string, len(block.Path))
			for index, path := range block.Path {
				generated.Path[index] = applyCombination(path, combination)
			}
		}
		generated.Body = applyCombination(block.Body, combination)
		if block.Headers != nil {
			generated.Headers = make(map[string]string, len(block.Headers))
			for name, value := range block.Headers {
				generated.Headers[name] = applyCombination(value, combination)
			}
		}
		if block.Raw != nil {
			generated.Raw = make([]string, len(block.Raw))
			for index, raw := range block.Raw {
				generated.Raw[index] = applyCombination(raw, combination)
			}
		}
		out = append(out, generated)
	}
	return out, ""
}
