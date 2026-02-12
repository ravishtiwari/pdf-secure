package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"securepdf-engine/pkg/consts"
	"securepdf-engine/pkg/options"
	"securepdf-engine/pkg/pdf"
	"securepdf-engine/pkg/policy"
	"securepdf-engine/pkg/receipt"
)

type engineOptValues []string

func (values *engineOptValues) String() string {
	return strings.Join(*values, ",")
}

func (values *engineOptValues) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("engine-opt must be non-empty")
	}
	*values = append(*values, value)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		printUsage(os.Stdout)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "secure":
		if err := runSecure(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			var exitErr *exitError
			if errors.As(err, &exitErr) {
				if code, ok := receipt.ExitCodeForError(exitErr.code); ok {
					os.Exit(code)
				}
			}
			os.Exit(1)
		}
	case "help", "-h", "--help":
		printUsage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage(os.Stderr)
		os.Exit(1)
	}
}

type exitError struct {
	code string
	err  error
}

func (e *exitError) Error() string {
	return e.err.Error()
}

func (e *exitError) Unwrap() error {
	return e.err
}

func runSecure(args []string) error {
	flags := flag.NewFlagSet("secure", flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	var (
		inputPath   = flags.String("in", "", "input PDF path")
		outputPath  = flags.String("out", "", "output PDF path")
		policyPath  = flags.String("policy", "", "policy JSON path")
		receiptPath = flags.String("receipt", "", "receipt JSON path")
		engineOpts  engineOptValues
	)

	flags.Var(&engineOpts, "engine-opt", "engine option key=value (repeatable)")

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printSecureUsage(os.Stdout)
			return nil
		}
		printSecureUsage(os.Stderr)
		return err
	}

	missing := missingFlags(*inputPath, *outputPath, *policyPath, *receiptPath)
	if len(missing) > 0 {
		printSecureUsage(os.Stderr)
		return fmt.Errorf("missing required flags: %s", strings.Join(missing, ", "))
	}

	// 1. Parse engine options
	opts, err := options.Parse(engineOpts)
	if err != nil {
		res := receipt.NewErrorWithDetails(
			consts.EngineVersion,
			"1.0",
			receipt.ErrInternalError,
			"invalid engine option",
			map[string]string{"error": err.Error()},
		)
		_ = res.Save(*receiptPath)
		return &exitError{code: receipt.ErrInternalError, err: fmt.Errorf("engine options error: %w", err)}
	}

	// 2. Load Policy + validate with options
	p, validation, err := policy.LoadWithOptions(*policyPath, opts)
	if err != nil {
		res := receipt.NewErrorWithDetails(
			consts.EngineVersion,
			"1.0",
			receipt.ErrPolicyInvalid,
			"policy parse error",
			map[string]string{"error": err.Error()},
		)
		_ = res.Save(*receiptPath)
		return &exitError{code: receipt.ErrPolicyInvalid, err: fmt.Errorf("policy error: %w", err)}
	}

	if validation != nil && !validation.Valid {
		code := receipt.ErrPolicyInvalid
		message := "policy invalid"
		var details map[string]string
		if validation.Error != nil {
			code = validation.Error.Code
			message = validation.Error.Message
			details = validation.Error.Details
		}
		res := receipt.NewErrorWithDetails(
			consts.EngineVersion,
			p.PolicyVersion,
			code,
			message,
			details,
		)
		res.Warnings = append(res.Warnings, validation.Warnings...)
		_ = res.Save(*receiptPath)
		return &exitError{code: code, err: fmt.Errorf("policy validation failed: %s", message)}
	}

	// 4. Run PDF processor
	processor := pdf.NewProcessor(p, *inputPath, *outputPath, opts)
	res, err := processor.Process()

	// Append validation warnings to result (so they are not lost on success)
	if validation != nil && len(validation.Warnings) > 0 {
		res.Warnings = append(res.Warnings, validation.Warnings...)
	}

	// 5. Write Receipt
	if saveErr := res.Save(*receiptPath); saveErr != nil {
		return fmt.Errorf("failed to save receipt: %w", saveErr)
	}

	if err != nil {
		code := receipt.ErrInternalError
		if res.Error != nil {
			code = res.Error.Code
		}
		return &exitError{code: code, err: fmt.Errorf("PDF processing failed: %w", err)}
	}

	if res.OK {
		fmt.Printf("✓ PDF secured successfully: %s\n", *outputPath)
		if len(res.Warnings) > 0 {
			fmt.Printf("  Warnings:\n")
			for _, w := range res.Warnings {
				fmt.Printf("    - [%s] %s\n", w.Code, w.Message)
			}
		}
	}

	return nil
}

func missingFlags(inputPath, outputPath, policyPath, receiptPath string) []string {
	var missing []string
	if inputPath == "" {
		missing = append(missing, "--in")
	}
	if outputPath == "" {
		missing = append(missing, "--out")
	}
	if policyPath == "" {
		missing = append(missing, "--policy")
	}
	if receiptPath == "" {
		missing = append(missing, "--receipt")
	}
	return missing
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "SecurePDF Engine")
	fmt.Fprintln(output, "")
	fmt.Fprintln(output, "Usage:")
	fmt.Fprintln(output, "  securepdf-engine <command> [options]")
	fmt.Fprintln(output, "")
	fmt.Fprintln(output, "Commands:")
	fmt.Fprintln(output, "  secure   Secure a PDF with a policy")
	fmt.Fprintln(output, "  help     Show this help text")
	fmt.Fprintln(output, "")
	fmt.Fprintln(output, "Run 'securepdf-engine secure --help' for command flags.")
}

func printSecureUsage(output io.Writer) {
	fmt.Fprintln(output, "Usage:")
	fmt.Fprintln(output, "  securepdf-engine secure --in <input.pdf> --out <secured.pdf>")
	fmt.Fprintln(output, "    --policy <policy.json> --receipt <receipt.json> [--engine-opt key=value]")
	fmt.Fprintln(output, "")
	fmt.Fprintln(output, "Options:")
	fmt.Fprintln(output, "  --in          Input PDF path")
	fmt.Fprintln(output, "  --out         Output PDF path")
	fmt.Fprintln(output, "  --policy      Policy JSON path")
	fmt.Fprintln(output, "  --receipt     Receipt JSON path")
	fmt.Fprintln(output, "  --engine-opt  Engine option key=value (repeatable)")
}
