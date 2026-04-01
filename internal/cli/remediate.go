package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/stormbane-security/bosun/internal/cve"
	"github.com/stormbane-security/bosun/pkg/generator"
	gh "github.com/stormbane-security/bosun/pkg/github"
	"github.com/stormbane-security/bosun/pkg/matcher"
	"github.com/stormbane-security/bosun/pkg/patcher"
	"github.com/stormbane-security/bosun/pkg/plan"
	"github.com/stormbane-security/bosun/internal/tracer"
	"github.com/stormbane-security/bosun/internal/verifier"
)

// runRemediate implements the full-loop remediation pipeline:
//
//  1. Read Beacon findings
//  2. Trace findings to source repos
//  3. Match findings to remediations
//  4. Generate Terraform / workflow code
//  5. Create PRs
//  6. Track deployment and trigger verification rescan
func runRemediate() error {
	if len(os.Args) < 4 || os.Args[2] != "--input" {
		return fmt.Errorf("usage: bosun remediate --input <beacon-output.json> [--org <github-org>] [--repo <owner/repo>] [--dry-run]")
	}

	var (
		inputPath  string
		org        string
		targetRepo string
		dryRun     bool
		beaconURL  string
	)

	for i := 2; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--input":
			i++
			if i < len(os.Args) {
				inputPath = os.Args[i]
			}
		case "--org":
			i++
			if i < len(os.Args) {
				org = os.Args[i]
			}
		case "--repo":
			i++
			if i < len(os.Args) {
				targetRepo = os.Args[i]
			}
		case "--beacon-url":
			i++
			if i < len(os.Args) {
				beaconURL = os.Args[i]
			}
		case "--dry-run":
			dryRun = true
		}
	}

	if inputPath == "" {
		return fmt.Errorf("--input is required")
	}

	ghToken := os.Getenv("GITHUB_TOKEN")
	if ghToken == "" {
		ghToken = os.Getenv("BOSUN_GITHUB_TOKEN")
	}

	// 1. Read findings.
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("reading input: %w", err)
	}

	var findings []matcher.Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		return fmt.Errorf("parsing findings: %w", err)
	}

	fmt.Fprintf(os.Stderr, "bosun: loaded %d findings\n", len(findings))

	// 2. Match findings to remediations.
	plan := matcher.Match(findings)
	fmt.Fprintf(os.Stderr, "bosun: %d remediations matched\n", len(plan.Remediations))

	if len(plan.Remediations) == 0 {
		fmt.Println("No actionable remediations found.")
		return nil
	}

	// 3. Trace assets to repos (if org is specified).
	repoLinks := make(map[string]string)
	if org != "" && ghToken != "" {
		fmt.Fprintf(os.Stderr, "bosun: tracing assets to repos in %s...\n", org)
		t := tracer.New(ghToken)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		for _, f := range findings {
			if f.Asset == "" {
				continue
			}
			// Build a resource from the finding's evidence.
			resource := resourceFromFinding(f)
			if resource == nil {
				continue
			}

			links, err := t.Trace(ctx, org, *resource)
			if err != nil {
				continue
			}
			if len(links) > 0 {
				repoLinks[f.Asset] = links[0].Repo
				fmt.Fprintf(os.Stderr, "  %s → %s (%s)\n", f.Asset, links[0].Repo, links[0].Method)
			}
		}
	}

	// 4. Generate code.
	files, err := generator.Generate(plan)
	if err != nil {
		return fmt.Errorf("generating: %w", err)
	}

	fmt.Fprintf(os.Stderr, "bosun: generated %d files\n", len(files))

	if dryRun {
		for path, content := range files {
			fmt.Printf("--- %s ---\n%s\n\n", path, content)
		}
		return nil
	}

	// 5. Write files and create PR.
	if targetRepo == "" {
		// Without a target repo, just output the files.
		for path, content := range files {
			fmt.Printf("--- %s ---\n%s\n\n", path, content)
		}
		fmt.Fprintf(os.Stderr, "bosun: no --repo specified, output to stdout. Use --repo to create a PR.\n")
		return nil
	}

	// Write to a temp dir and create a PR.
	tmpDir, err := os.MkdirTemp("", "bosun-*")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	written, err := patcher.Apply(tmpDir, files)
	if err != nil {
		return fmt.Errorf("writing files: %w", err)
	}

	fmt.Fprintf(os.Stderr, "bosun: wrote %d files to %s\n", len(written), tmpDir)

	if ghToken == "" {
		return fmt.Errorf("GITHUB_TOKEN required to create PRs")
	}

	// Parse owner/repo.
	parts := splitRepo(targetRepo)
	if len(parts) != 2 {
		return fmt.Errorf("invalid --repo format, expected owner/repo")
	}

	client := gh.New(ghToken)
	prURL, err := client.CreatePR(
		parts[0], parts[1],
		fmt.Sprintf("fix: security remediation — %d fixes", len(plan.Remediations)),
		buildPRBody(plan, files),
		"bosun/remediation",
		"main",
	)
	if err != nil {
		return fmt.Errorf("creating PR: %w", err)
	}

	fmt.Fprintf(os.Stderr, "bosun: PR created → %s\n", prURL)

	// 6. Track for verification.
	if beaconURL != "" {
		v := verifier.New(ghToken, beaconURL)
		for _, r := range plan.Remediations {
			v.Track(verifier.Verification{
				RemediationID: r.ID,
				PRURL:         prURL,
				Asset:         findAssetForRemediation(findings, r.CheckID),
				CheckID:       r.CheckID,
			})
		}
		fmt.Fprintf(os.Stderr, "bosun: tracking %d verifications — will rescan after deployment\n", len(v.Pending()))
	}

	// 7. Check for CVE-based upgrades.
	if ghToken != "" {
		cveFindings := toCVEFindings(findings)
		if len(cveFindings) > 0 {
			w := cve.New(ghToken)
			ctx := context.Background()
			upgrades, err := w.GenerateUpgrades(ctx, cveFindings, repoLinks)
			if err == nil && len(upgrades) > 0 {
				fmt.Fprintf(os.Stderr, "bosun: %d CVE upgrade PRs suggested\n", len(upgrades))
				for _, u := range upgrades {
					fmt.Fprintf(os.Stderr, "  %s: %s %s → %s (%s)\n",
						u.Repo, u.Package, u.CurrentVersion, u.TargetVersion, u.Advisory.CVEID)
				}
			}
		}
	}

	return nil
}

func resourceFromFinding(f matcher.Finding) *tracer.Resource {
	r := &tracer.Resource{}

	switch {
	case contains(f.CheckID, "gcp", "gke", "gcs"):
		r.Provider = "gcp"
	case contains(f.CheckID, "aws", "s3", "ec2", "eks"):
		r.Provider = "aws"
	default:
		return nil
	}

	switch {
	case contains(f.CheckID, "gke"):
		r.Service = "gke"
	case contains(f.CheckID, "eks"):
		r.Service = "eks"
	case contains(f.CheckID, "s3"):
		r.Service = "s3"
	case contains(f.CheckID, "ec2"):
		r.Service = "ec2"
	case contains(f.CheckID, "gcs", "bucket"):
		r.Service = "gcs"
	default:
		r.Service = "unknown"
	}

	r.Name = f.Asset
	return r
}

func contains(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if len(s) >= len(sub) && stringContains(s, sub) {
			return true
		}
	}
	return false
}

func stringContains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func splitRepo(repo string) []string {
	parts := make([]string, 0, 2)
	idx := 0
	for i, c := range repo {
		if c == '/' {
			parts = append(parts, repo[idx:i])
			idx = i + 1
		}
	}
	if idx < len(repo) {
		parts = append(parts, repo[idx:])
	}
	return parts
}

func buildPRBody(plan *plan.Plan, files map[string]string) string {
	body := "## Security Remediation\n\nGenerated by Bosun from Beacon scan findings.\n\n### Remediations\n\n"
	for _, r := range plan.Remediations {
		body += fmt.Sprintf("- **%s** (%s): %s\n", r.ID, r.CheckID, r.Description)
	}
	body += fmt.Sprintf("\n### Files (%d)\n\n", len(files))
	for path := range files {
		body += fmt.Sprintf("- `%s`\n", path)
	}
	body += "\n---\nGenerated by Bosun\n"
	return body
}

func findAssetForRemediation(findings []matcher.Finding, checkID string) string {
	for _, f := range findings {
		if f.CheckID == checkID {
			return f.Asset
		}
	}
	return ""
}

func toCVEFindings(findings []matcher.Finding) []cve.Finding {
	var result []cve.Finding
	for _, f := range findings {
		result = append(result, cve.Finding{
			CheckID:  f.CheckID,
			Asset:    f.Asset,
			Title:    f.Title,
			Evidence: f.Evidence,
		})
	}
	return result
}
