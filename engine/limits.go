package main

import (
	"os"
	"strconv"
)

// envLimit reads an integer budget from the environment. Invalid, zero, or
// negative values fall back to the local default so a malformed environment
// cannot accidentally turn a request into an unbounded read.
func envLimit(name string, fallback int) int {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}
