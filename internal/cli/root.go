package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/stormbane-security/bosun/internal/generator"
	"github.com/stormbane-security/bosun/internal/matcher"
	"github.com/stormbane-security/bosun/internal/plan"
)

// Execute runs the bosun CLI.
func Execute(version string) error {
	if len(os.Args) < 2 {
		return printUsage(version)
	}

	switch os.Args[1] {
	case "plan":
		return runPlan()
	case "generate":
		return runGenerate()
	case "remediate":
		return runRemediate()
	case "version":
		fmt.Printf("bosun %s\n", version)
		return nil
	case "help", "-h", "--help":
		return printUsage(version)
	default:
		return fmt.Errorf("unknown command %q — run 'bosun help' for usage", os.Args[1])
	}
}

func printUsage(version string) error {
	fmt.Printf(`bosun %s — security remediation code generator

Usage:
  bosun plan       --input <beacon-output.json>   Create a remediation plan from Beacon findings
  bosun generate   --plan <plan.json>              Generate Terraform + CI/CD from a plan
  bosun remediate  --input <beacon-output.json>    Full-loop: match → generate → PR → verify
  bosun version                                    Print version

Remediate flags:
  --input <file>       Beacon JSON output (required)
  --org <github-org>   GitHub org to trace assets to repos
  --repo <owner/repo>  Target repo for PR creation
  --beacon-url <url>   Beacon API URL for verification rescans
  --dry-run            Print generated files without creating PR

Bosun reads Beacon scan output and generates:
  - Terraform modules to harden cloud infrastructure (AWS, GCP)
  - GitHub Actions workflows with security best practices
  - Pull requests with the generated changes

`, version)
	return nil
}

func runPlan() error {
	if len(os.Args) < 4 || os.Args[2] != "--input" {
		return fmt.Errorf("usage: bosun plan --input <beacon-output.json>")
	}

	inputPath := os.Args[3]
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("reading input: %w", err)
	}

	var findings []matcher.Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		return fmt.Errorf("parsing findings: %w", err)
	}

	p := matcher.Match(findings)

	out, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling plan: %w", err)
	}

	fmt.Println(string(out))
	return nil
}

func runGenerate() error {
	if len(os.Args) < 4 || os.Args[2] != "--plan" {
		return fmt.Errorf("usage: bosun generate --plan <plan.json>")
	}

	planPath := os.Args[3]
	data, err := os.ReadFile(planPath)
	if err != nil {
		return fmt.Errorf("reading plan: %w", err)
	}

	var p plan.Plan
	if err := json.Unmarshal(data, &p); err != nil {
		return fmt.Errorf("parsing plan: %w", err)
	}

	files, err := generator.Generate(&p)
	if err != nil {
		return fmt.Errorf("generating: %w", err)
	}

	for path, content := range files {
		fmt.Printf("--- %s ---\n%s\n", path, content)
	}

	return nil
}
