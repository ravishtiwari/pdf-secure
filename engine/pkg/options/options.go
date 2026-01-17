package options

import (
	"fmt"
	"strconv"
	"strings"
)

// EngineOptions holds runtime configuration flags provided via --engine-opt.
type EngineOptions struct {
	RejectWeakCrypto bool
	TimeoutMs        int
	MaxInputMB       int
	MaxMemoryMB      int
}

// Default returns EngineOptions populated with safe defaults.
func Default() *EngineOptions {
	return &EngineOptions{
		RejectWeakCrypto: false,
		TimeoutMs:        60000,
		MaxInputMB:       200,
		MaxMemoryMB:      512,
	}
}

// Parse parses --engine-opt key=value entries into EngineOptions.
func Parse(entries []string) (*EngineOptions, error) {
	opts := Default()

	for _, entry := range entries {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid engine-opt format %q (expected key=value)", entry)
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "reject_weak_crypto":
			parsed, err := parseBool(value)
			if err != nil {
				return nil, fmt.Errorf("invalid reject_weak_crypto value %q", value)
			}
			opts.RejectWeakCrypto = parsed
		case "timeout_ms":
			parsed, err := strconv.Atoi(value)
			if err != nil || parsed < 0 {
				return nil, fmt.Errorf("invalid timeout_ms value %q", value)
			}
			opts.TimeoutMs = parsed
		case "max_input_mb":
			parsed, err := strconv.Atoi(value)
			if err != nil || parsed <= 0 {
				return nil, fmt.Errorf("invalid max_input_mb value %q", value)
			}
			opts.MaxInputMB = parsed
		case "max_memory_mb":
			parsed, err := strconv.Atoi(value)
			if err != nil || parsed <= 0 {
				return nil, fmt.Errorf("invalid max_memory_mb value %q", value)
			}
			opts.MaxMemoryMB = parsed
		default:
			// Unknown options ignored for forward compatibility
		}
	}

	return opts, nil
}

func parseBool(raw string) (bool, error) {
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("invalid bool: %s", raw)
	}
}
