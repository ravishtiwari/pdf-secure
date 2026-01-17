package options

import (
	"testing"
)

func TestDefault(t *testing.T) {
	opts := Default()

	if opts.RejectWeakCrypto != false {
		t.Error("expected RejectWeakCrypto default to be false")
	}
	if opts.TimeoutMs != 60000 {
		t.Errorf("expected TimeoutMs=60000, got %d", opts.TimeoutMs)
	}
	if opts.MaxInputMB != 200 {
		t.Errorf("expected MaxInputMB=200, got %d", opts.MaxInputMB)
	}
	if opts.MaxMemoryMB != 512 {
		t.Errorf("expected MaxMemoryMB=512, got %d", opts.MaxMemoryMB)
	}
}

func TestParseEmpty(t *testing.T) {
	opts, err := Parse([]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.RejectWeakCrypto != false {
		t.Error("expected default RejectWeakCrypto=false")
	}
}

func TestParseRejectWeakCrypto(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"reject_weak_crypto=true", true},
		{"reject_weak_crypto=1", true},
		{"reject_weak_crypto=yes", true},
		{"reject_weak_crypto=on", true},
		{"reject_weak_crypto=false", false},
		{"reject_weak_crypto=0", false},
		{"reject_weak_crypto=no", false},
		{"reject_weak_crypto=off", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			opts, err := Parse([]string{tt.input})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if opts.RejectWeakCrypto != tt.expected {
				t.Errorf("expected RejectWeakCrypto=%v, got %v", tt.expected, opts.RejectWeakCrypto)
			}
		})
	}
}

func TestParseRejectWeakCryptoInvalid(t *testing.T) {
	_, err := Parse([]string{"reject_weak_crypto=maybe"})
	if err == nil {
		t.Error("expected error for invalid bool value")
	}
}

func TestParseTimeoutMs(t *testing.T) {
	opts, err := Parse([]string{"timeout_ms=30000"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.TimeoutMs != 30000 {
		t.Errorf("expected TimeoutMs=30000, got %d", opts.TimeoutMs)
	}
}

func TestParseTimeoutMsInvalid(t *testing.T) {
	tests := []string{
		"timeout_ms=abc",
		"timeout_ms=-1",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			_, err := Parse([]string{input})
			if err == nil {
				t.Error("expected error for invalid timeout_ms")
			}
		})
	}
}

func TestParseMaxInputMB(t *testing.T) {
	opts, err := Parse([]string{"max_input_mb=500"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.MaxInputMB != 500 {
		t.Errorf("expected MaxInputMB=500, got %d", opts.MaxInputMB)
	}
}

func TestParseMaxInputMBInvalid(t *testing.T) {
	tests := []string{
		"max_input_mb=abc",
		"max_input_mb=0",
		"max_input_mb=-10",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			_, err := Parse([]string{input})
			if err == nil {
				t.Error("expected error for invalid max_input_mb")
			}
		})
	}
}

func TestParseMaxMemoryMB(t *testing.T) {
	opts, err := Parse([]string{"max_memory_mb=1024"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.MaxMemoryMB != 1024 {
		t.Errorf("expected MaxMemoryMB=1024, got %d", opts.MaxMemoryMB)
	}
}

func TestParseMaxMemoryMBInvalid(t *testing.T) {
	tests := []string{
		"max_memory_mb=abc",
		"max_memory_mb=0",
		"max_memory_mb=-10",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			_, err := Parse([]string{input})
			if err == nil {
				t.Error("expected error for invalid max_memory_mb")
			}
		})
	}
}

func TestParseMultipleOptions(t *testing.T) {
	entries := []string{
		"reject_weak_crypto=true",
		"timeout_ms=45000",
		"max_input_mb=100",
		"max_memory_mb=256",
	}

	opts, err := Parse(entries)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !opts.RejectWeakCrypto {
		t.Error("expected RejectWeakCrypto=true")
	}
	if opts.TimeoutMs != 45000 {
		t.Errorf("expected TimeoutMs=45000, got %d", opts.TimeoutMs)
	}
	if opts.MaxInputMB != 100 {
		t.Errorf("expected MaxInputMB=100, got %d", opts.MaxInputMB)
	}
	if opts.MaxMemoryMB != 256 {
		t.Errorf("expected MaxMemoryMB=256, got %d", opts.MaxMemoryMB)
	}
}

func TestParseUnknownOptionIgnored(t *testing.T) {
	opts, err := Parse([]string{"unknown_option=value"})
	if err != nil {
		t.Fatalf("unknown options should be ignored, got error: %v", err)
	}
	// Verify defaults still apply
	if opts.RejectWeakCrypto != false {
		t.Error("expected default values to remain")
	}
}

func TestParseInvalidFormat(t *testing.T) {
	tests := []string{
		"no_equals_sign",
		"=value_only",
		"",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			if input == "" {
				// Empty string in array should be caught
				_, err := Parse([]string{input})
				if err == nil {
					t.Error("expected error for empty entry")
				}
			} else {
				_, err := Parse([]string{input})
				if err == nil {
					t.Errorf("expected error for invalid format: %q", input)
				}
			}
		})
	}
}

func TestParseWhitespaceHandling(t *testing.T) {
	opts, err := Parse([]string{"  reject_weak_crypto  =  true  "})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !opts.RejectWeakCrypto {
		t.Error("expected whitespace to be trimmed and parsed correctly")
	}
}
