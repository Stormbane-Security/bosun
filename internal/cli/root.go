package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/stormbane/infra"
	"github.com/stormbane-security/bosun/pkg/catalog"
	"github.com/stormbane-security/bosun/pkg/generator"
	"github.com/stormbane-security/bosun/pkg/generator/backstage"
	"github.com/stormbane-security/bosun/pkg/matcher"
	"github.com/stormbane-security/bosun/pkg/plan"
	"github.com/stormbane-security/bosun/pkg/scaffold"
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
	case "scaffold":
		return runScaffold()
	case "catalog":
		return runCatalog()
	case "backstage":
		return runBackstage()
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
  bosun scaffold   --id <catalog-id> [--param k=v] Generate new security-hardened infrastructure
  bosun scaffold   --query "description"           AI-matched scaffold from natural language
  bosun catalog    [--provider <provider>]          List available infrastructure patterns
  bosun backstage                                   Generate Backstage software templates
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

func runScaffold() error {
	var (
		catalogID string
		query     string
		params    = make(map[string]string)
	)

	for i := 2; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--id":
			i++
			if i < len(os.Args) {
				catalogID = os.Args[i]
			}
		case "--query":
			i++
			if i < len(os.Args) {
				query = os.Args[i]
			}
		case "--param":
			i++
			if i < len(os.Args) {
				k, v, ok := strings.Cut(os.Args[i], "=")
				if ok {
					params[k] = v
				}
			}
		}
	}

	// If query is provided, do intent matching first.
	if query != "" && catalogID == "" {
		matches := scaffold.MatchIntent(query)
		if len(matches) == 0 {
			return fmt.Errorf("no catalog entries match %q — run 'bosun catalog' to see all", query)
		}
		fmt.Fprintf(os.Stderr, "bosun: matched %d patterns for %q\n\n", len(matches), query)
		for i, m := range matches {
			if i >= 5 {
				break
			}
			fmt.Fprintf(os.Stderr, "  %s — %s\n    %s\n\n", m.ID, m.Name, m.Description)
		}
		// Use the top match.
		catalogID = matches[0].ID
		fmt.Fprintf(os.Stderr, "bosun: using top match: %s\n\n", catalogID)
	}

	if catalogID == "" {
		return fmt.Errorf("usage: bosun scaffold --id <catalog-id> [--param key=value ...]\n       bosun scaffold --query \"I need a kubernetes cluster on GCP\"")
	}

	result, err := scaffold.Run(scaffold.Request{
		CatalogID: catalogID,
		Params:    params,
	})
	if err != nil {
		if result != nil && len(result.MissingParams) > 0 {
			fmt.Fprintf(os.Stderr, "bosun: missing required parameters:\n")
			entry := result.Entry
			for _, name := range result.MissingParams {
				for _, p := range entry.Params {
					if p.Name == name {
						fmt.Fprintf(os.Stderr, "  --param %s=<%s>\n", p.Name, p.Label)
					}
				}
			}
			return err
		}
		return err
	}

	fmt.Fprintf(os.Stderr, "bosun: scaffolded %s — %d files\n", result.Entry.Name, len(result.Files))
	if len(result.Entry.SecurityNotes) > 0 {
		fmt.Fprintf(os.Stderr, "\nSecurity hardening applied:\n")
		for _, note := range result.Entry.SecurityNotes {
			fmt.Fprintf(os.Stderr, "  ✓ %s\n", note)
		}
		fmt.Fprintln(os.Stderr)
	}

	for path, content := range result.Files {
		fmt.Printf("--- %s ---\n%s\n\n", path, content)
	}

	return nil
}

func runCatalog() error {
	provider := ""
	category := ""
	for i := 2; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--provider":
			i++
			if i < len(os.Args) {
				provider = os.Args[i]
			}
		case "--category":
			i++
			if i < len(os.Args) {
				category = os.Args[i]
			}
		}
	}

	entries := catalog.All()
	if provider != "" {
		entries = catalog.ByProvider(infra.Technology(provider))
	}
	if category != "" {
		var filtered []catalog.Entry
		for _, e := range entries {
			if e.Category == category {
				filtered = append(filtered, e)
			}
		}
		entries = filtered
	}

	if len(entries) == 0 {
		fmt.Println("No catalog entries found.")
		return nil
	}

	fmt.Printf("Available infrastructure patterns (%d):\n\n", len(entries))
	currentProvider := infra.Technology("")
	for _, e := range entries {
		if e.Provider != currentProvider {
			currentProvider = e.Provider
			fmt.Printf("── %s ──\n", strings.ToUpper(string(currentProvider)))
		}
		fmt.Printf("  %-25s %s\n", e.ID, e.Name)
		fmt.Printf("  %-25s %s\n", "", e.Description)
		if len(e.Params) > 0 {
			paramNames := make([]string, len(e.Params))
			for i, p := range e.Params {
				if p.Required {
					paramNames[i] = p.Name + " (required)"
				} else {
					paramNames[i] = p.Name
				}
			}
			fmt.Printf("  %-25s params: %s\n", "", strings.Join(paramNames, ", "))
		}
		fmt.Println()
	}

	return nil
}

func runBackstage() error {
	files := backstage.GenerateAll()

	fmt.Fprintf(os.Stderr, "bosun: generated %d Backstage template files\n\n", len(files))
	for path, content := range files {
		fmt.Printf("--- %s ---\n%s\n\n", path, content)
	}

	fmt.Fprintf(os.Stderr, "To use these templates:\n")
	fmt.Fprintf(os.Stderr, "  1. Write files to a repo: bosun backstage | bosun apply --repo your-org/backstage-templates\n")
	fmt.Fprintf(os.Stderr, "  2. Add to Backstage app-config.yaml:\n")
	fmt.Fprintf(os.Stderr, "     catalog:\n")
	fmt.Fprintf(os.Stderr, "       locations:\n")
	fmt.Fprintf(os.Stderr, "         - type: url\n")
	fmt.Fprintf(os.Stderr, "           target: https://github.com/your-org/backstage-templates/blob/main/backstage/catalog-info.yaml\n")

	return nil
}
