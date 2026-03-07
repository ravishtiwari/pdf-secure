"""CLI entry point for SecurePDF.

Usage:
    python -m securepdf secure --in input.pdf --out output.pdf --policy policy.json --receipt receipt.json

Examples:
    # Basic encryption
    python -m securepdf secure --in doc.pdf --out secured.pdf --policy policy.json --receipt receipt.json

    # With engine options
    python -m securepdf secure --in doc.pdf --out secured.pdf --policy policy.json --receipt receipt.json \\
        --engine-opt reject_weak_crypto=true --engine-opt timeout_ms=30000
"""

import argparse
import sys
import json
from pathlib import Path

from securepdf import secure_pdf, Policy, __version__
from securepdf.models.receipt import Receipt
from securepdf.exception import SecurePDFException


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="python -m securepdf",
        description="SecurePDF - Secure PDF documents with encryption, labels, and provenance tracking",
        epilog="For detailed documentation, visit: https://github.com/ravishtiwari/pdf-secure",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        help="Available commands",
        required=False,
    )

    # secure command
    secure_parser = subparsers.add_parser(
        "secure",
        help="Secure a PDF with encryption, labels, and provenance",
        description="""
Secure a PDF document according to a security policy.

The policy controls encryption settings, visible/invisible labels,
provenance tracking, and tamper detection. The engine produces a
structured receipt with transformation details and integrity hashes.

Examples:
    # Basic encryption only
    python -m securepdf secure --in doc.pdf --out secured.pdf \\
        --policy policy.json --receipt receipt.json

    # With custom engine binary
    python -m securepdf secure --in doc.pdf --out secured.pdf \\
        --policy policy.json --receipt receipt.json \\
        --engine-bin ./bin/securepdf-engine

    # With runtime options
    python -m securepdf secure --in doc.pdf --out secured.pdf \\
        --policy policy.json --receipt receipt.json \\
        --engine-opt reject_weak_crypto=true \\
        --engine-opt timeout_ms=30000 \\
        --engine-opt max_input_mb=100
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    secure_parser.add_argument(
        "--in",
        dest="input",
        required=True,
        metavar="PATH",
        help="Input PDF file path",
    )
    secure_parser.add_argument(
        "--out",
        dest="output",
        required=True,
        metavar="PATH",
        help="Output secured PDF file path",
    )
    secure_parser.add_argument(
        "--policy",
        required=True,
        metavar="PATH",
        help="Policy JSON file path (defines security settings)",
    )
    secure_parser.add_argument(
        "--receipt",
        required=True,
        metavar="PATH",
        help="Receipt JSON output path (transformation audit trail)",
    )
    secure_parser.add_argument(
        "--engine-bin",
        metavar="PATH",
        help="Path to securepdf-engine binary (default: securepdf-engine in PATH)",
    )
    secure_parser.add_argument(
        "--engine-opt",
        action="append",
        metavar="KEY=VALUE",
        help="""Engine runtime option (can be specified multiple times).

Supported options:
  reject_weak_crypto=true|false  - Reject weak crypto profiles (default: false)
  timeout_ms=N                   - Processing timeout in milliseconds (default: 60000)
  max_input_mb=N                 - Maximum input file size in MB (default: 200)
  max_memory_mb=N                - Maximum memory usage in MB (default: 512)
        """,
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        print(
            "\nError: No command specified. Use 'secure' to process a PDF.",
            file=sys.stderr,
        )
        sys.exit(1)

    if args.command == "secure":
        try:
            # Validate input file exists
            input_path = Path(args.input)
            if not input_path.exists():
                print(
                    f"❌ Error: Input PDF file not found: {args.input}", file=sys.stderr
                )
                print(f"   Please check the file path and try again.", file=sys.stderr)
                sys.exit(3)

            # Load policy from JSON file
            policy_path = Path(args.policy)
            if not policy_path.exists():
                print(
                    f"❌ Error: Policy file not found: {args.policy}", file=sys.stderr
                )
                print(
                    f"   Create a policy.json file or check the path.", file=sys.stderr
                )
                sys.exit(2)

            with open(policy_path, "r") as f:
                policy_data = json.load(f)

            # Convert dict to Policy object if needed
            if isinstance(policy_data, dict):
                policy = Policy.from_dict(policy_data)
            else:
                policy = policy_data

            # Parse engine options (keep values as strings — engine handles parsing)
            engine_options = {}
            if args.engine_opt:
                for opt in args.engine_opt:
                    if "=" not in opt:
                        print(
                            f"❌ Error: Invalid engine option format: '{opt}'",
                            file=sys.stderr,
                        )
                        print(
                            f"   Expected format: key=value (e.g., reject_weak_crypto=true)",
                            file=sys.stderr,
                        )
                        sys.exit(1)
                    key, value = opt.split("=", 1)
                    engine_options[key] = value

            # Prepare secure_pdf arguments
            kwargs = {
                "input_path": args.input,
                "output_path": args.output,
                "policy": policy,
            }

            # Add optional engine_bin if provided
            if args.engine_bin:
                kwargs["engine_bin"] = args.engine_bin

            # Add engine_opts if any
            if engine_options:
                kwargs["engine_opts"] = engine_options

            # Call secure_pdf
            receipt = secure_pdf(**kwargs)

            # Save receipt
            receipt_path = Path(args.receipt)
            with open(receipt_path, "w") as f:
                json.dump(receipt.to_dict(), f, indent=2, default=str)

            # Print success
            if receipt.ok:
                print(f"✅ PDF secured successfully!")
                print(f"   Input:   {args.input}")
                print(f"   Output:  {args.output}")
                print(f"   Receipt: {args.receipt}")

                if receipt.document_id:
                    print(f"   Document ID: {receipt.document_id}")
                if receipt.copy_id:
                    print(f"   Copy ID:     {receipt.copy_id}")

                if receipt.warnings:
                    print(f"\n⚠️  Warnings ({len(receipt.warnings)}):")
                    for w in receipt.warnings:
                        print(f"   [{w.code}] {w.message}")

                sys.exit(0)
            else:
                print("❌ PDF processing failed", file=sys.stderr)
                if receipt.error:
                    print(
                        f"   Error: [{receipt.error.code}] {receipt.error.message}",
                        file=sys.stderr,
                    )
                    if receipt.error.details:
                        print(f"   Details:", file=sys.stderr)
                        for k, v in receipt.error.details.items():
                            print(f"     {k}: {v}", file=sys.stderr)
                print(f"\n   Receipt saved to: {args.receipt}", file=sys.stderr)
                sys.exit(4)

        except SecurePDFException as e:
            # SecurePDF exceptions may have a receipt attached
            # Always write the receipt if available
            if hasattr(e, "receipt") and e.receipt:
                receipt_path = Path(args.receipt)
                with open(receipt_path, "w") as f:
                    json.dump(e.receipt.to_dict(), f, indent=2, default=str)
                print(f"❌ PDF processing failed: {e}", file=sys.stderr)
                print(f"   Receipt saved to: {args.receipt}", file=sys.stderr)
            else:
                print(f"❌ Error: {e}", file=sys.stderr)
            sys.exit(4)
        except FileNotFoundError as e:
            print(f"❌ Error: File not found: {e}", file=sys.stderr)
            sys.exit(3)
        except json.JSONDecodeError as e:
            print(f"❌ Error: Invalid JSON in policy file", file=sys.stderr)
            print(f"   {e}", file=sys.stderr)
            sys.exit(2)
        except KeyboardInterrupt:
            print("\n⚠️  Operation cancelled by user", file=sys.stderr)
            sys.exit(130)
        except Exception as e:
            print(f"❌ Unexpected error: {e}", file=sys.stderr)
            print(f"   Please report this issue if it persists.", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
