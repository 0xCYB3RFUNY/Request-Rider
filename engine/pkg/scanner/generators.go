package scanner

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

// Генератори значень, які nuclei підставляє сам.
//
// Усе тут звірено з оригіналом, а не згадано: підстановку перевірялося запуском
// nuclei v3.11.1 на ехо-фістурі, яка повертає назад сами запит.
//
//	{{randstr}}       -> 3KCM2qmEGJd8y4dN4wLaHl8jgRu      28 знаків
//	{{randstr:10}}    -> запит не надсилається взагалі
//	{{num}}           -> поза fuzzing-контекстом запит не надсилається
//
// Останні два — не недолік нашої імплементації, а виміряна поведінка самого
// nuclei. Тому `{{randstr:10}}` відмовляється з поясненням, а не підставляється
// «якось»: надсилати запит, який nuclei не надсилає, означало б видати вердикт за
// перевірку, якої не було.

// randStrLength is how long a bare `{{randstr}}` is.
//
// Measured on v3.11.1: `GET /x={{randstr}}` went out as
// `/x=3KCM2qmEGJd8y4dN4wLaHl8jgRu` — 28 characters, upper case, lower case and
// digits, no separators.
const randStrLength = 28

// randStrAlphabet is the set that value was drawn from. Punctuation is not in
// it: a generator that produced `{{randstr}}` containing a slash or a quote
// would change the request's shape, and a template that wanted that would have
// written it.
const randStrAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// generateRandStr draws one `{{randstr}}` value.
//
// `crypto/rand` rather than `math/rand` because the value is sent to a target:
// a predictable one would put a token in someone else's request log that reads as
// random and is not.
func generateRandStr() (string, error) {
	out := make([]byte, randStrLength)
	max := big.NewInt(int64(len(randStrAlphabet)))
	for index := range out {
		pick, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("cannot draw a random character: %s", oneLine(err.Error()))
		}
		out[index] = randStrAlphabet[pick.Int64()]
	}
	return string(out), nil
}

// generatorRefusals names the placeholders this runner does not generate, and why
// for the ones that look like they should work.
//
// The `{{randstr:N}}` case is here because it is measured, not assumed: nuclei
// v3.11.1 sends nothing at all for it, so substituting a value would produce a
// request nuclei never makes.
func generatorRefusal(name string) string {
	trimmed := strings.TrimSpace(name)
	switch {
	case trimmed == "randstr":
		return ""
	case strings.HasPrefix(trimmed, "randstr:"):
		return fmt.Sprintf("{{%s}} asks for a length this runner does not implement, and nuclei v3.11.1 "+
			"sends nothing at all for the argumented form — measured on a probe template, where "+
			"`{{randstr}}` went out as 28 characters and `{{randstr:10}}` produced no request", trimmed)
	case trimmed == "num":
		return "{{num}} is a fuzzing engine's counter, and it is substituted only inside a fuzzing block; " +
			"measured on v3.11.1, a probe template with a bare {{num}} in an http path sent no request"
	case trimmed == "rand_base":
		// Handled as a spelling of the target host, so it never reaches here.
		return ""
	default:
		return ""
	}
}
