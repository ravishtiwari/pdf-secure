// Package options provides engine runtime configuration parsing.
//
// Engine options are runtime settings that control engine behavior but are not
// part of the policy schema. They are passed via --engine-opt flags on the CLI.
//
// Supported Options:
//   - reject_weak_crypto: When true, reject policies that use compat/legacy crypto profiles
//   - timeout_ms: Maximum execution time in milliseconds (default: 60000)
//   - max_input_mb: Maximum input PDF size in megabytes (default: 200)
//   - max_memory_mb: Maximum memory usage in megabytes (default: 512)
//
// I need to figure out a way to ensure that I am not manually setting these values in Python SDK.
// There should be way or mechanism to ensure that these values are consistent across all SDKs.
// May be a JSON or MessagePack contract between engine and SDKs.
// This will help in maintaining consistency and avoid manual updates in multiple SDK
// > I do not at the moment have plan to support Node.js or PHP SDKs.
//
// Usage:
//
//	securepdf-engine secure --engine-opt reject_weak_crypto=true --engine-opt timeout_ms=30000
//
// Unknown options are silently ignored for forward compatibility, allowing newer
// SDKs to pass options that older engines don't understand.
package options

import (
	"fmt"
	"strconv"
	"strings"
)

// EngineOptions holds runtime configuration flags provided via --engine-opt.
// These settings control engine behavior independently of the policy.
type EngineOptions struct {
	// RejectWeakCrypto when true causes validation to fail if the policy
	// requests a weak crypto profile (compat or legacy). Default: false.
	RejectWeakCrypto bool

	// TimeoutMs is the maximum execution time in milliseconds.
	// A value of 0 disables the timeout. Default: 60000 (60 seconds).
	TimeoutMs int

	// MaxInputMB is the maximum allowed input PDF file size in megabytes.
	// Requests with larger inputs are rejected. Default: 200 MB.
	MaxInputMB int

	// MaxMemoryMB is the maximum memory the engine may use in megabytes.
	// Default: 512 MB.
	MaxMemoryMB int
}

// Default returns EngineOptions populated with safe defaults.
// These defaults are suitable for most production deployments:
//   - RejectWeakCrypto: false (allows compat/legacy for backward compatibility)
//   - TimeoutMs: 60000 (60 seconds)
//   - MaxInputMB: 200 (200 MB max input)
//   - MaxMemoryMB: 512 (512 MB max memory)
func Default() *EngineOptions {
	return &EngineOptions{
		RejectWeakCrypto: false,
		TimeoutMs:        60000,
		MaxInputMB:       200,
		MaxMemoryMB:      512,
	}
}

// Parse parses --engine-opt key=value entries into EngineOptions.
// Unknown keys are silently ignored for forward compatibility.
//
// Returns an error if:
//   - An entry is not in key=value format
//   - A known key has an invalid value (e.g., non-numeric timeout_ms)
//
// Example:
//
//	opts, err := Parse([]string{"reject_weak_crypto=true", "timeout_ms=30000"})
func Parse(entries []string) (*EngineOptions, error) {
	opts := Default()

	for _, entry := range entries {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid engine-opt format %q (expected key=value)", entry)
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if key == "" {
			return nil, fmt.Errorf("invalid engine-opt format %q (empty key)", entry)
		}

		if value == "" {
			return nil, fmt.Errorf("invalid engine-opt format %q (empty value)", entry)
		}

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
