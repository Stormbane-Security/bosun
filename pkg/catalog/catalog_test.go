package catalog_test

import (
	"testing"

	"github.com/stormbane-security/bosun/pkg/catalog"
)

func TestAll_NotEmpty(t *testing.T) {
	entries := catalog.All()
	if len(entries) == 0 {
		t.Fatal("catalog should not be empty")
	}
}

func TestByProvider_GCP(t *testing.T) {
	entries := catalog.ByProvider("gcp")
	if len(entries) == 0 {
		t.Fatal("expected GCP entries")
	}
	for _, e := range entries {
		if e.Provider != "gcp" {
			t.Errorf("expected provider 'gcp', got %q", e.Provider)
		}
	}
}

func TestByProvider_AWS(t *testing.T) {
	entries := catalog.ByProvider("aws")
	if len(entries) == 0 {
		t.Fatal("expected AWS entries")
	}
}

func TestByID_Found(t *testing.T) {
	e, ok := catalog.ByID("gcp-gke-cluster")
	if !ok {
		t.Fatal("expected to find gcp-gke-cluster")
	}
	if e.Name == "" {
		t.Error("expected non-empty name")
	}
	if len(e.Templates) == 0 {
		t.Error("expected at least one template ref")
	}
}

func TestByID_NotFound(t *testing.T) {
	_, ok := catalog.ByID("nonexistent")
	if ok {
		t.Error("expected not found for nonexistent ID")
	}
}

func TestByCategory(t *testing.T) {
	entries := catalog.ByCategory("identity")
	if len(entries) == 0 {
		t.Fatal("expected identity entries")
	}
	for _, e := range entries {
		if e.Category != "identity" {
			t.Errorf("expected category 'identity', got %q", e.Category)
		}
	}
}

func TestAll_UniqueIDs(t *testing.T) {
	seen := make(map[string]bool)
	for _, e := range catalog.All() {
		if seen[e.ID] {
			t.Errorf("duplicate catalog ID: %s", e.ID)
		}
		seen[e.ID] = true
	}
}

func TestAll_RequiredFields(t *testing.T) {
	for _, e := range catalog.All() {
		if e.ID == "" {
			t.Error("entry missing ID")
		}
		if e.Name == "" {
			t.Errorf("entry %s missing Name", e.ID)
		}
		if e.Provider == "" {
			t.Errorf("entry %s missing Provider", e.ID)
		}
		if e.Category == "" {
			t.Errorf("entry %s missing Category", e.ID)
		}
		if len(e.Templates) == 0 {
			t.Errorf("entry %s has no templates", e.ID)
		}
		if len(e.Tags) == 0 {
			t.Errorf("entry %s has no tags", e.ID)
		}
	}
}
