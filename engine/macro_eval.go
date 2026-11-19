package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"math/big"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const maxMacroRecursionDepth = 16

// EvaluateRequestMacros applies inline Hackvertor-style macro tags ({{...}})
// to URL, Headers and Body of a requestInput.
// If no macro tag "{{", is present, it returns the input immediately with zero overhead.
func EvaluateRequestMacros(input requestInput, secrets map[string]string) requestInput {
	// Fast-path: check if any macros exist across all fields
	hasMacro := strings.Contains(input.URL, "{{") || strings.Contains(input.Body, "{{")
	if !hasMacro {
		for _, v := range input.Headers {
			if strings.Contains(v, "{{") {
				hasMacro = true
				break
			}
		}
	}
	if !hasMacro {
		return input
	}

	out := input
	if strings.Contains(out.URL, "{{") {
		out.URL = EvaluateMacroText(out.URL, secrets)
	}
	if strings.Contains(out.Body, "{{") {
		out.Body = EvaluateMacroText(out.Body, secrets)
	}
	if len(out.Headers) > 0 {
		newHeaders := make(map[string]string, len(out.Headers))
		for k, v := range out.Headers {
			if strings.Contains(v, "{{") {
				newHeaders[k] = EvaluateMacroText(v, secrets)
			} else {
				newHeaders[k] = v
			}
		}
		out.Headers = newHeaders
	}
	return out
}

// EvaluateMacroText evaluates all {{...}} tags inside text, supporting nested
// functions up to maxMacroRecursionDepth levels.
func EvaluateMacroText(text string, secrets map[string]string) string {
	if !strings.Contains(text, "{{") {
		return text
	}

	current := text
	for depth := 0; depth < maxMacroRecursionDepth; depth++ {
		startIdx := strings.LastIndex(current, "{{")
		if startIdx == -1 {
			break
		}
		endIdx := strings.Index(current[startIdx:], "}}")
		if endIdx == -1 {
			// Unclosed tag: return as-is
			break
		}
		endIdx += startIdx

		tagContent := current[startIdx+2 : endIdx]
		evaluated := evalSingleTag(tagContent, secrets)

		current = current[:startIdx] + evaluated + current[endIdx+2:]
	}
	return current
}

func evalSingleTag(raw string, secrets map[string]string) string {
	tag := strings.TrimSpace(raw)
	if tag == "" {
		return ""
	}

	// Secret lookup: {{$secret.NAME}}
	if strings.HasPrefix(tag, "$secret.") {
		key := strings.TrimPrefix(tag, "$secret.")
		if secrets != nil {
			if val, ok := secrets[key]; ok {
				return val
			}
		}
		if envVal := os.Getenv(key); envVal != "" {
			return envVal
		}
		return ""
	}

	// Function call: name(arg1, arg2, ...)
	openParen := strings.IndexByte(tag, '(')
	closeParen := strings.LastIndexByte(tag, ')')
	if openParen == -1 || closeParen == -1 || closeParen <= openParen {
		// Not a function call, check plain variable or return tag
		if secrets != nil {
			if val, ok := secrets[tag]; ok {
				return val
			}
		}
		return tag
	}

	fnName := strings.ToLower(strings.TrimSpace(tag[:openParen]))
	argsRaw := tag[openParen+1 : closeParen]
	args := splitMacroArgs(argsRaw)

	return executeMacroFunction(fnName, args, secrets)
}

func splitMacroArgs(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var args []string
	var current strings.Builder
	inQuote := false
	quoteChar := byte(0)
	braceDepth := 0
	parenDepth := 0
	bracketDepth := 0

	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if inQuote {
			if c == quoteChar {
				inQuote = false
			} else {
				current.WriteByte(c)
			}
		} else {
			if (c == '"' || c == '\'') && braceDepth == 0 && bracketDepth == 0 {
				inQuote = true
				quoteChar = c
			} else if c == '{' {
				braceDepth++
				current.WriteByte(c)
			} else if c == '}' {
				if braceDepth > 0 {
					braceDepth--
				}
				current.WriteByte(c)
			} else if c == '(' {
				parenDepth++
				current.WriteByte(c)
			} else if c == ')' {
				if parenDepth > 0 {
					parenDepth--
				}
				current.WriteByte(c)
			} else if c == '[' {
				bracketDepth++
				current.WriteByte(c)
			} else if c == ']' {
				if bracketDepth > 0 {
					bracketDepth--
				}
				current.WriteByte(c)
			} else if c == ',' && braceDepth == 0 && parenDepth == 0 && bracketDepth == 0 {
				args = append(args, strings.TrimSpace(current.String()))
				current.Reset()
			} else {
				current.WriteByte(c)
			}
		}
	}
	if current.Len() > 0 || len(args) > 0 {
		args = append(args, strings.TrimSpace(current.String()))
	}
	return args
}

func executeMacroFunction(name string, args []string, secrets map[string]string) string {
	arg0 := ""
	if len(args) > 0 {
		arg0 = args[0]
	}

	switch name {
	// --- Encoding & Hashing ---
	case "b64":
		return base64.StdEncoding.EncodeToString([]byte(arg0))

	case "b64url":
		return base64.RawURLEncoding.EncodeToString([]byte(arg0))

	case "url_enc":
		return url.QueryEscape(arg0)

	case "hex":
		return hex.EncodeToString([]byte(arg0))

	case "html_enc":
		return html.EscapeString(arg0)

	case "sha256":
		h := sha256.Sum256([]byte(arg0))
		return hex.EncodeToString(h[:])

	case "md5":
		h := md5.Sum([]byte(arg0))
		return hex.EncodeToString(h[:])

	case "hmac_sha256":
		if len(args) < 2 {
			return ""
		}
		key := []byte(args[0])
		data := []byte(args[1])
		mac := hmac.New(sha256.New, key)
		mac.Write(data)
		return hex.EncodeToString(mac.Sum(nil))

	// --- Dynamic Generators ---
	case "uuid4":
		return generateUUIDv4()

	case "ts_sec":
		return strconv.FormatInt(time.Now().Unix(), 10)

	case "ts_ms":
		return strconv.FormatInt(time.Now().UnixMilli(), 10)

	case "rand_int":
		minVal := int64(1000)
		maxVal := int64(9999)
		if len(args) >= 1 {
			if n, err := strconv.ParseInt(args[0], 10, 64); err == nil {
				minVal = n
			}
		}
		if len(args) >= 2 {
			if n, err := strconv.ParseInt(args[1], 10, 64); err == nil {
				maxVal = n
			}
		}
		if maxVal < minVal {
			minVal, maxVal = maxVal, minVal
		}
		diff := maxVal - minVal + 1
		nBig, err := rand.Int(rand.Reader, big.NewInt(diff))
		if err != nil {
			return strconv.FormatInt(minVal, 10)
		}
		return strconv.FormatInt(minVal+nBig.Int64(), 10)

	case "rand_str":
		length := 16
		if len(args) >= 1 {
			if l, err := strconv.Atoi(args[0]); err == nil && l > 0 && l <= 4096 {
				length = l
			}
		}
		const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		b := make([]byte, length)
		for i := range b {
			idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
			if err != nil {
				b[i] = charset[i%len(charset)]
			} else {
				b[i] = charset[idx.Int64()]
			}
		}
		return string(b)

	case "nonce":
		byteLen := 16
		if len(args) >= 1 {
			if l, err := strconv.Atoi(args[0]); err == nil && l > 0 && l <= 1024 {
				byteLen = l
			}
		}
		b := make([]byte, byteLen)
		_, _ = rand.Read(b)
		return hex.EncodeToString(b)

	// --- JWT Helper ---
	case "jwt_sign":
		// jwt_sign(header_json, payload_json, secret_or_key)
		if len(args) < 3 {
			return ""
		}
		hdr := base64.RawURLEncoding.EncodeToString([]byte(args[0]))
		pld := base64.RawURLEncoding.EncodeToString([]byte(args[1]))
		signingInput := hdr + "." + pld
		key := []byte(args[2])
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(signingInput))
		sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		return signingInput + "." + sig

	default:
		return fmt.Sprintf("{{%s(%s)}}", name, strings.Join(args, ","))
	}
}

func generateUUIDv4() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
