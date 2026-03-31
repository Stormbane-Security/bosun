// Package matcher maps Beacon findings to remediations. It takes a slice of
// findings (from Beacon JSON output) and produces a Plan with the
// appropriate remediation templates and parameters.
package matcher

import (
	"strings"

	"github.com/stormbane-security/bosun/internal/plan"
)

// Finding is the subset of Beacon's finding.Finding that Bosun needs.
// We define our own type to avoid importing Beacon as a dependency.
type Finding struct {
	CheckID     string            `json:"check_id"`
	Severity    string            `json:"severity"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Asset       string            `json:"asset"`
	Evidence    map[string]any    `json:"evidence"`
}

// Match produces a Plan from a list of Beacon findings. Each finding is
// matched against known remediation rules. Unmatched findings are silently
// skipped — Bosun only generates code for things it knows how to fix.
func Match(findings []Finding) *plan.Plan {
	p := &plan.Plan{
		Version: "1",
		Vars:    make(map[string]string),
	}

	seen := make(map[string]bool)
	for _, f := range findings {
		r, ok := matchFinding(f)
		if !ok {
			continue
		}
		// Deduplicate by remediation ID.
		if seen[r.ID] {
			continue
		}
		seen[r.ID] = true
		p.Remediations = append(p.Remediations, r)

		// Infer provider from check ID prefix.
		if p.Provider == "" {
			p.Provider = inferProvider(f.CheckID)
		}
	}

	return p
}

func matchFinding(f Finding) (plan.Remediation, bool) {
	r := plan.Remediation{
		CheckID:  f.CheckID,
		Severity: f.Severity,
		Params:   make(map[string]string),
	}

	switch {
	// --- GCP ---
	case f.CheckID == "cloud.gcp.bucket_public":
		r.ID = "gcs-private"
		r.Kind = "terraform"
		r.Template = "gcp/gcs_private"
		r.Description = "Make GCS bucket private with uniform bucket-level access"
		if name, ok := extractEvidence(f, "bucket"); ok {
			r.Params["bucket_name"] = name
		}

	case f.CheckID == "cloud.gcp.iam_primitive_role":
		r.ID = "gcp-iam-least-privilege"
		r.Kind = "terraform"
		r.Template = "gcp/iam_least_privilege"
		r.Description = "Replace primitive IAM roles with least-privilege predefined roles"

	case f.CheckID == "cloud.gcp.gke_legacy_auth":
		r.ID = "gke-hardened"
		r.Kind = "terraform"
		r.Template = "gcp/gke_hardened"
		r.Description = "Harden GKE cluster: disable legacy auth, enable shielded nodes, workload identity"

	case f.CheckID == "cloud.gcp.sql_public":
		r.ID = "cloudsql-private"
		r.Kind = "terraform"
		r.Template = "gcp/cloudsql_private"
		r.Description = "Remove 0.0.0.0/0 from Cloud SQL authorized networks"

	// --- AWS ---
	case f.CheckID == "cloud.aws.s3_public":
		r.ID = "s3-private"
		r.Kind = "terraform"
		r.Template = "aws/s3_private"
		r.Description = "Enable S3 public access block and encryption"
		if name, ok := extractEvidence(f, "bucket"); ok {
			r.Params["bucket_name"] = name
		}

	case f.CheckID == "cloud.aws.ec2_public_ip":
		r.ID = "ec2-private"
		r.Kind = "terraform"
		r.Template = "aws/ec2_security_group"
		r.Description = "Restrict EC2 security group to remove 0.0.0.0/0 ingress"

	case f.CheckID == "cloud.aws.iam_mfa_disabled":
		r.ID = "aws-iam-mfa"
		r.Kind = "terraform"
		r.Template = "aws/iam_mfa_policy"
		r.Description = "Enforce MFA for IAM users via policy condition"

	case f.CheckID == "cloud.aws.eks_public_endpoint":
		r.ID = "eks-private"
		r.Kind = "terraform"
		r.Template = "aws/eks_private"
		r.Description = "Disable public endpoint on EKS cluster"

	// --- CI/CD ---
	case f.CheckID == "ghaction.unpinned_action":
		r.ID = "pin-actions"
		r.Kind = "workflow"
		r.Template = "pin-actions"
		r.Description = "Pin GitHub Actions to full SHA hashes"

	case f.CheckID == "ghaction.excessive_permissions":
		r.ID = "minimal-permissions"
		r.Kind = "workflow"
		r.Template = "minimal-permissions"
		r.Description = "Set minimal GITHUB_TOKEN permissions"

	case strings.HasPrefix(f.CheckID, "supply_chain."):
		r.ID = "supply-chain-" + strings.TrimPrefix(f.CheckID, "supply_chain.")
		r.Kind = "both"
		r.Template = "docker-build-push"
		r.Description = "Add container signing, SBOM generation, and vulnerability scanning to build pipeline"

	default:
		return r, false
	}

	return r, true
}

func inferProvider(checkID string) string {
	switch {
	case strings.Contains(checkID, "gcp") || strings.Contains(checkID, "gke") || strings.Contains(checkID, "gcs"):
		return "gcp"
	case strings.Contains(checkID, "aws") || strings.Contains(checkID, "s3") || strings.Contains(checkID, "ec2") || strings.Contains(checkID, "eks"):
		return "aws"
	default:
		return ""
	}
}

func extractEvidence(f Finding, key string) (string, bool) {
	if f.Evidence == nil {
		return "", false
	}
	v, ok := f.Evidence[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}
