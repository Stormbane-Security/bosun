package matcher_test

import (
	"testing"

	"github.com/stormbane-security/bosun/internal/matcher"
)

func TestMatch_GCPBucketPublic(t *testing.T) {
	findings := []matcher.Finding{
		{
			CheckID:  "cloud.gcp.bucket_public",
			Severity: "high",
			Title:    "Public GCS bucket",
			Evidence: map[string]any{"bucket": "my-bucket"},
		},
	}

	p := matcher.Match(findings)
	if len(p.Remediations) != 1 {
		t.Fatalf("expected 1 remediation, got %d", len(p.Remediations))
	}

	r := p.Remediations[0]
	if r.ID != "gcs-private" {
		t.Errorf("expected ID 'gcs-private', got %q", r.ID)
	}
	if r.Template != "gcp/gcs_private" {
		t.Errorf("expected template 'gcp/gcs_private', got %q", r.Template)
	}
	if r.Params["bucket_name"] != "my-bucket" {
		t.Errorf("expected bucket_name 'my-bucket', got %q", r.Params["bucket_name"])
	}
	if p.Provider != "gcp" {
		t.Errorf("expected provider 'gcp', got %q", p.Provider)
	}
}

func TestMatch_AWSS3Public(t *testing.T) {
	findings := []matcher.Finding{
		{
			CheckID:  "cloud.aws.s3_public",
			Severity: "high",
			Title:    "Public S3 bucket",
			Evidence: map[string]any{"bucket": "test-bucket"},
		},
	}

	p := matcher.Match(findings)
	if len(p.Remediations) != 1 {
		t.Fatalf("expected 1 remediation, got %d", len(p.Remediations))
	}

	r := p.Remediations[0]
	if r.ID != "s3-private" {
		t.Errorf("expected ID 's3-private', got %q", r.ID)
	}
	if r.Kind != "terraform" {
		t.Errorf("expected kind 'terraform', got %q", r.Kind)
	}
	if p.Provider != "aws" {
		t.Errorf("expected provider 'aws', got %q", p.Provider)
	}
}

func TestMatch_UnknownCheckID_Skipped(t *testing.T) {
	findings := []matcher.Finding{
		{
			CheckID: "unknown.check.id",
			Title:   "Unknown finding",
		},
	}

	p := matcher.Match(findings)
	if len(p.Remediations) != 0 {
		t.Errorf("expected 0 remediations for unknown check, got %d", len(p.Remediations))
	}
}

func TestMatch_DuplicateFindings_Deduplicated(t *testing.T) {
	findings := []matcher.Finding{
		{CheckID: "cloud.gcp.bucket_public", Evidence: map[string]any{"bucket": "b1"}},
		{CheckID: "cloud.gcp.bucket_public", Evidence: map[string]any{"bucket": "b2"}},
	}

	p := matcher.Match(findings)
	if len(p.Remediations) != 1 {
		t.Errorf("expected 1 deduplicated remediation, got %d", len(p.Remediations))
	}
}

func TestMatch_SupplyChain_KindBoth(t *testing.T) {
	findings := []matcher.Finding{
		{CheckID: "supply_chain.no_sbom", Severity: "medium"},
	}

	p := matcher.Match(findings)
	if len(p.Remediations) != 1 {
		t.Fatalf("expected 1 remediation, got %d", len(p.Remediations))
	}

	r := p.Remediations[0]
	if r.Kind != "both" {
		t.Errorf("expected kind 'both', got %q", r.Kind)
	}
	if r.Template != "docker-build-push" {
		t.Errorf("expected template 'docker-build-push', got %q", r.Template)
	}
}

func TestMatch_CICDFindings(t *testing.T) {
	findings := []matcher.Finding{
		{CheckID: "ghaction.unpinned_action", Severity: "medium"},
		{CheckID: "ghaction.excessive_permissions", Severity: "medium"},
	}

	p := matcher.Match(findings)
	if len(p.Remediations) != 2 {
		t.Fatalf("expected 2 remediations, got %d", len(p.Remediations))
	}

	ids := make(map[string]bool)
	for _, r := range p.Remediations {
		ids[r.ID] = true
		if r.Kind != "workflow" {
			t.Errorf("expected kind 'workflow' for %s, got %q", r.ID, r.Kind)
		}
	}

	if !ids["pin-actions"] {
		t.Error("expected 'pin-actions' remediation")
	}
	if !ids["minimal-permissions"] {
		t.Error("expected 'minimal-permissions' remediation")
	}
}

func TestMatch_OktaMFANotEnforced(t *testing.T) {
	findings := []matcher.Finding{
		{CheckID: "iam.okta_mfa_not_enforced", Severity: "critical"},
	}

	p := matcher.Match(findings)
	if len(p.Remediations) != 1 {
		t.Fatalf("expected 1 remediation, got %d", len(p.Remediations))
	}

	r := p.Remediations[0]
	if r.ID != "okta-mfa" {
		t.Errorf("expected ID 'okta-mfa', got %q", r.ID)
	}
	if r.Template != "okta/mfa_policy" {
		t.Errorf("expected template 'okta/mfa_policy', got %q", r.Template)
	}
	if r.Kind != "terraform" {
		t.Errorf("expected kind 'terraform', got %q", r.Kind)
	}
	if p.Provider != "okta" {
		t.Errorf("expected provider 'okta', got %q", p.Provider)
	}
}

func TestMatch_OktaMultipleFindings(t *testing.T) {
	findings := []matcher.Finding{
		{CheckID: "iam.okta_mfa_not_enforced"},
		{CheckID: "iam.okta_weak_password_policy"},
		{CheckID: "iam.okta_no_session_timeout"},
		{CheckID: "iam.okta_threat_insight_disabled"},
		{CheckID: "iam.okta_no_group_rules"},
	}

	p := matcher.Match(findings)
	if len(p.Remediations) != 5 {
		t.Fatalf("expected 5 remediations, got %d", len(p.Remediations))
	}

	ids := make(map[string]bool)
	for _, r := range p.Remediations {
		ids[r.ID] = true
	}

	expected := []string{"okta-mfa", "okta-password", "okta-session", "okta-threat-insight", "okta-groups"}
	for _, id := range expected {
		if !ids[id] {
			t.Errorf("expected %q remediation", id)
		}
	}
}

func TestMatch_MultipleProviders(t *testing.T) {
	findings := []matcher.Finding{
		{CheckID: "cloud.gcp.bucket_public", Evidence: map[string]any{"bucket": "b1"}},
		{CheckID: "cloud.aws.s3_public", Evidence: map[string]any{"bucket": "b2"}},
		{CheckID: "cloud.aws.iam_mfa_disabled"},
		{CheckID: "cloud.aws.eks_public_endpoint"},
	}

	p := matcher.Match(findings)
	if len(p.Remediations) != 4 {
		t.Fatalf("expected 4 remediations, got %d", len(p.Remediations))
	}

	// Provider should be set to the first finding's provider.
	if p.Provider != "gcp" {
		t.Errorf("expected provider 'gcp' (from first finding), got %q", p.Provider)
	}
}

func TestMatch_EmptyFindings(t *testing.T) {
	p := matcher.Match(nil)
	if len(p.Remediations) != 0 {
		t.Errorf("expected 0 remediations, got %d", len(p.Remediations))
	}
	if p.Vars == nil {
		t.Error("expected Vars to be initialized")
	}
}
