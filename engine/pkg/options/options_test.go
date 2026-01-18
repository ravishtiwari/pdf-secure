package options

import "testing"

func TestParseDefaults(t *testing.T) {
	opts, err := Parse(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.TimeoutMs != 60000 || opts.MaxInputMB != 200 || opts.MaxMemoryMB != 512 {
		t.Error("defaults not applied as expected")
	}
}

func TestParseValues(t *testing.T) {
	opts, err := Parse([]string{
		"reject_weak_crypto=true",
		"timeout_ms=1234",
		"max_input_mb=10",
		"max_memory_mb=256",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !opts.RejectWeakCrypto {
		t.Error("expected reject_weak_crypto to be true")
	}
	if opts.TimeoutMs != 1234 || opts.MaxInputMB != 10 || opts.MaxMemoryMB != 256 {
		t.Error("parsed numeric values do not match")
	}
}

func TestParseInvalidFormats(t *testing.T) {
	_, err := Parse([]string{"invalid_format"})
	if err == nil {
		t.Error("expected error for invalid format")
	}
}

func TestParseInvalidValues(t *testing.T) {
	_, err := Parse([]string{"reject_weak_crypto=maybe"})
	if err == nil {
		t.Error("expected error for invalid bool")
	}
	_, err = Parse([]string{"timeout_ms=-1"})
	if err == nil {
		t.Error("expected error for invalid timeout")
	}
	_, err = Parse([]string{"max_input_mb=0"})
	if err == nil {
		t.Error("expected error for invalid max_input_mb")
	}
}
