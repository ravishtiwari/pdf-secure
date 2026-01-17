package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

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

	flags.Var(&engineOpts, "engine-opt", "engine option k=v (repeatable)")

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

	// 1. Load Policy
	p, err := policy.Load(*policyPath)
	if err != nil {
		return fmt.Errorf("policy error: %w", err)
	}

	// 2. Prepare Stub Receipt (transformation not yet implemented)
	res := receipt.NewErrorWithDetails(
		"0.0.1",
		p.PolicyVersion,
		receipt.ErrInternalError,
		"Transformation pipeline not yet implemented",
		map[string]string{"reason": "stub"},
	)

	// 3. Write Receipt
	if err := res.Save(*receiptPath); err != nil {
		return fmt.Errorf("failed to save receipt: %w", err)
	}

	fmt.Printf("Policy loaded: version=%s, encryption=%v (Password: ***)\n", p.PolicyVersion, p.Encryption.Enabled)
	return fmt.Errorf("transformation not implemented")
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
