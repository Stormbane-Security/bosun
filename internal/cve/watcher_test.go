package cve_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stormbane-security/bosun/internal/cve"
)

func TestGenerateUpgrades_WithCVEInEvidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/advisories":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{
					"ghsa_id":  "GHSA-1234",
					"cve_id":   "CVE-2024-1234",
					"summary":  "Critical vuln in example-pkg",
					"severity": "critical",
					"vulnerabilities": []map[string]any{
						{
							"package": map[string]string{
								"ecosystem": "Go",
								"name":      "github.com/example/pkg",
							},
							"vulnerable_version_range": "< 1.5.0",
							"first_patched_version": map[string]string{
								"identifier": "1.5.0",
							},
						},
					},
				},
			})
		case "/repos/myorg/myapp/contents/go.mod":
			_, _ = w.Write([]byte("module myapp\n\ngo 1.21\n\nrequire github.com/example/pkg v1.4.0\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	w := cve.New("test-token")
	w.SetBaseURL(srv.URL)

	findings := []cve.Finding{
		{
			CheckID:  "supply_chain.outdated_dep",
			Asset:    "myapp.example.com",
			Title:    "Outdated dependency",
			Evidence: map[string]any{"cve": "CVE-2024-1234"},
		},
	}
	repoLinks := map[string]string{
		"myapp.example.com": "myorg/myapp",
	}

	upgrades, err := w.GenerateUpgrades(context.Background(), findings, repoLinks)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(upgrades) != 1 {
		t.Fatalf("expected 1 upgrade, got %d", len(upgrades))
	}

	u := upgrades[0]
	if u.Repo != "myorg/myapp" {
		t.Errorf("expected repo 'myorg/myapp', got %q", u.Repo)
	}
	if u.Package != "github.com/example/pkg" {
		t.Errorf("expected package 'github.com/example/pkg', got %q", u.Package)
	}
	if u.TargetVersion != "1.5.0" {
		t.Errorf("expected target version '1.5.0', got %q", u.TargetVersion)
	}
	if u.CurrentVersion != "v1.4.0" {
		t.Errorf("expected current version 'v1.4.0', got %q", u.CurrentVersion)
	}
}

func TestGenerateUpgrades_NoCVE(t *testing.T) {
	w := cve.New("test-token")

	findings := []cve.Finding{
		{
			CheckID: "cors.wildcard",
			Asset:   "example.com",
			Title:   "CORS wildcard",
		},
	}

	upgrades, err := w.GenerateUpgrades(context.Background(), findings, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(upgrades) != 0 {
		t.Errorf("expected 0 upgrades for non-CVE finding, got %d", len(upgrades))
	}
}

func TestGenerateUpgrades_CVEInTitle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/advisories":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{
					"cve_id":   "CVE-2024-5678",
					"summary":  "XSS in template lib",
					"severity": "high",
					"vulnerabilities": []map[string]any{
						{
							"package": map[string]string{
								"ecosystem": "npm",
								"name":      "template-lib",
							},
							"first_patched_version": map[string]string{
								"identifier": "2.0.1",
							},
						},
					},
				},
			})
		case "/repos/myorg/frontend/contents/package.json":
			_, _ = w.Write([]byte(`{"dependencies":{"template-lib":"^1.9.0"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	w := cve.New("test-token")
	w.SetBaseURL(srv.URL)

	findings := []cve.Finding{
		{
			CheckID: "supply_chain.vuln",
			Asset:   "app.example.com",
			Title:   "Vulnerable dependency (CVE-2024-5678)",
		},
	}
	repoLinks := map[string]string{
		"app.example.com": "myorg/frontend",
	}

	upgrades, err := w.GenerateUpgrades(context.Background(), findings, repoLinks)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(upgrades) != 1 {
		t.Fatalf("expected 1 upgrade, got %d", len(upgrades))
	}
	if upgrades[0].Advisory.CVEID != "CVE-2024-5678" {
		t.Errorf("expected CVE-2024-5678, got %q", upgrades[0].Advisory.CVEID)
	}
}

func TestGenerateUpgrades_NoRepoLink(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{
				"cve_id":   "CVE-2024-9999",
				"severity": "medium",
				"vulnerabilities": []map[string]any{
					{
						"package": map[string]string{"ecosystem": "Go", "name": "example"},
						"first_patched_version": map[string]string{"identifier": "1.0.0"},
					},
				},
			},
		})
	}))
	defer srv.Close()

	w := cve.New("test-token")
	w.SetBaseURL(srv.URL)

	findings := []cve.Finding{
		{
			CheckID:  "supply_chain.vuln",
			Asset:    "orphan.example.com",
			Evidence: map[string]any{"cve": "CVE-2024-9999"},
		},
	}

	// No repo links — should produce no upgrades.
	upgrades, err := w.GenerateUpgrades(context.Background(), findings, map[string]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(upgrades) != 0 {
		t.Errorf("expected 0 upgrades without repo link, got %d", len(upgrades))
	}
}

func TestGenerateUpgrades_ContextCancelled(t *testing.T) {
	w := cve.New("test-token")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	findings := []cve.Finding{
		{
			CheckID:  "supply_chain.vuln",
			Asset:    "app.example.com",
			Evidence: map[string]any{"cve": "CVE-2024-1111"},
		},
	}

	upgrades, err := w.GenerateUpgrades(ctx, findings, map[string]string{
		"app.example.com": "myorg/app",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(upgrades) != 0 {
		t.Errorf("expected 0 upgrades for cancelled context, got %d", len(upgrades))
	}
}
