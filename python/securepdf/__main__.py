"""CLI entry point for SecurePDF.

Usage:
    python -m securepdf secure --in input.pdf --out output.pdf --policy policy.json --receipt receipt.json
"""

import argparse
import sys
import json
from pathlib import Path

from securepdf import secure_pdf, Policy
from securepdf.models.receipt import Receipt


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="python -m securepdf",
        description="SecurePDF - PDF security transformation tool",
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # secure command
    secure_parser = subparsers.add_parser("secure", help="Secure a PDF with a policy")
    secure_parser.add_argument(
        "--in", dest="input", required=True, help="Input PDF path"
    )
    secure_parser.add_argument(
        "--out", dest="output", required=True, help="Output PDF path"
    )
    secure_parser.add_argument("--policy", required=True, help="Policy JSON path")
    secure_parser.add_argument("--receipt", required=True, help="Receipt JSON path")
    secure_parser.add_argument(
        "--engine-bin", help="Path to securepdf-engine binary (optional)"
    )
    secure_parser.add_argument(
        "--engine-opt", action="append", help="Engine option key=value (repeatable)"
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "secure":
        try:
            # Load policy from JSON file
            policy_path = Path(args.policy)
            if not policy_path.exists():
                print(f"Error: Policy file not found: {args.policy}", file=sys.stderr)
                sys.exit(2)

            with open(policy_path, "r") as f:
                policy_data = json.load(f)

            # Convert dict to Policy object if needed
            if isinstance(policy_data, dict):
                policy = Policy.from_dict(policy_data)
            else:
                policy = policy_data

            # Parse engine options
            engine_options = {}
            if args.engine_opt:
                for opt in args.engine_opt:
                    if "=" not in opt:
                        print(
                            f"Error: Invalid engine option format: {opt} (expected key=value)",
                            file=sys.stderr,
                        )
                        sys.exit(1)
                    key, value = opt.split("=", 1)
                    # Try to parse value as bool/int/float
                    if value.lower() in ("true", "false"):
                        value = value.lower() == "true"
                    elif value.isdigit():
                        value = int(value)
                    else:
                        try:
                            value = float(value)
                        except ValueError:
                            pass  # Keep as string
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
                print(f"PDF secured successfully: {args.output}")
                if receipt.warnings:
                    print("  Warnings:")
                    for w in receipt.warnings:
                        print(f"    - [{w.code}] {w.message}")
                sys.exit(0)
            else:
                print(
                    f"PDF processing failed: {receipt.error.message}", file=sys.stderr
                )
                sys.exit(4)

        except FileNotFoundError as e:
            print(f"Error: File not found: {e}", file=sys.stderr)
            sys.exit(3)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
