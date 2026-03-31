package scaffold_test

import (
	"testing"

	"github.com/stormbane-security/bosun/pkg/scaffold"
)

func TestRun_GKECluster(t *testing.T) {
	result, err := scaffold.Run(scaffold.Request{
		CatalogID: "gcp-gke-cluster",
		Params: map[string]string{
			"cluster_name": "prod-cluster",
			"project_id":   "my-project",
			"region":       "us-central1",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Files) == 0 {
		t.Fatal("expected generated files")
	}
	if result.Entry.ID != "gcp-gke-cluster" {
		t.Errorf("expected entry ID 'gcp-gke-cluster', got %q", result.Entry.ID)
	}
}

func TestRun_MissingRequiredParam(t *testing.T) {
	result, err := scaffold.Run(scaffold.Request{
		CatalogID: "gcp-gke-cluster",
		Params:    map[string]string{},
	})
	if err == nil {
		t.Fatal("expected error for missing params")
	}
	if result == nil {
		t.Fatal("expected result with missing params info")
	}
	if len(result.MissingParams) == 0 {
		t.Error("expected MissingParams to be populated")
	}
}

func TestRun_DefaultParams(t *testing.T) {
	result, err := scaffold.Run(scaffold.Request{
		CatalogID: "aws-s3-bucket",
		Params: map[string]string{
			"bucket_name": "my-bucket",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Files) == 0 {
		t.Fatal("expected generated files")
	}
}

func TestRun_InvalidCatalogID(t *testing.T) {
	_, err := scaffold.Run(scaffold.Request{
		CatalogID: "nonexistent",
	})
	if err == nil {
		t.Fatal("expected error for invalid catalog ID")
	}
}

func TestRun_OktaBaseline(t *testing.T) {
	result, err := scaffold.Run(scaffold.Request{
		CatalogID: "okta-org-baseline",
		Params: map[string]string{
			"org_name": "mycompany",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Okta baseline has 5 templates.
	if len(result.Files) < 5 {
		t.Errorf("expected at least 5 files for okta baseline, got %d", len(result.Files))
	}
}

func TestMatchIntent_Kubernetes(t *testing.T) {
	matches := scaffold.MatchIntent("kubernetes gke cluster on gcp")
	if len(matches) == 0 {
		t.Fatal("expected matches for 'kubernetes gke cluster on gcp'")
	}
	top := matches[0]
	if top.ID != "gcp-gke-cluster" {
		t.Errorf("expected top match 'gcp-gke-cluster', got %q", top.ID)
	}
}

func TestMatchIntent_GCP(t *testing.T) {
	matches := scaffold.MatchIntent("gcp storage bucket")
	if len(matches) == 0 {
		t.Fatal("expected matches for 'gcp storage bucket'")
	}
	if matches[0].ID != "gcp-gcs-bucket" {
		t.Errorf("expected top match 'gcp-gcs-bucket', got %q", matches[0].ID)
	}
}

func TestMatchIntent_NoMatch(t *testing.T) {
	matches := scaffold.MatchIntent("xyzzy frobnicator")
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for gibberish, got %d", len(matches))
	}
}

func TestMatchIntent_CICD(t *testing.T) {
	matches := scaffold.MatchIntent("docker build pipeline ci")
	if len(matches) == 0 {
		t.Fatal("expected matches for docker build pipeline")
	}
}
