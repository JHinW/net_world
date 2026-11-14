package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// loadEnvFile reads KEY=VALUE pairs from a custom .env file and sets them in
// the current process environment via os.Setenv. CLI flags still take precedence
// over values loaded from the file.
func loadEnvFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open env file %q: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}

		eqIdx := strings.IndexByte(line, '=')
		if eqIdx <= 0 {
			return fmt.Errorf("env file %q line %d: expected KEY=VALUE", path, lineNum)
		}

		key := strings.TrimSpace(line[:eqIdx])
		rawVal := strings.TrimSpace(line[eqIdx+1:])
		val, err := parseEnvValue(rawVal)
		if err != nil {
			return fmt.Errorf("env file %q line %d (%s): %w", path, lineNum, key, err)
		}
		if err := os.Setenv(key, val); err != nil {
			return fmt.Errorf("set env %s: %w", key, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read env file %q: %w", path, err)
	}
	return nil
}

func parseEnvValue(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	quote := raw[0]
	if quote == '"' || quote == '\'' {
		for i := 1; i < len(raw); i++ {
			if quote == '"' && raw[i] == '\\' && i+1 < len(raw) {
				i++
				continue
			}
			if raw[i] == quote {
				trailing := strings.TrimSpace(raw[i+1:])
				if trailing != "" && !strings.HasPrefix(trailing, "#") {
					return "", fmt.Errorf("unexpected trailing characters after closing quote")
				}
				inner := raw[1:i]
				if quote == '"' {
					inner = unescapeDoubleQuoted(inner)
				}
				return inner, nil
			}
		}
		return "", fmt.Errorf("unterminated quoted value")
	}

	// Unquoted value: strip inline comment preceded by whitespace.
	for i := 0; i < len(raw); i++ {
		if raw[i] == '#' && i > 0 && (raw[i-1] == ' ' || raw[i-1] == '\t') {
			return strings.TrimSpace(raw[:i]), nil
		}
	}
	return strings.TrimSpace(raw), nil
}

func unescapeDoubleQuoted(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'n':
				b.WriteByte('\n')
				i++
				continue
			case 'r':
				b.WriteByte('\r')
				i++
				continue
			case 't':
				b.WriteByte('\t')
				i++
				continue
			case '"', '\\':
				b.WriteByte(s[i+1])
				i++
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
