package backstage_test

import (
	"strings"
	"testing"

	"github.com/stormbane-security/bosun/pkg/catalog"
	"github.com/stormbane-security/bosun/pkg/generator/backstage"
)

func TestGenerateAll_ProducesFiles(t *testing.T) {
	files := backstage.GenerateAll()
	if len(files) == 0 {
		t.Fatal("expected generated files")
	}

	// Should have catalog-info.yaml.
	if _, ok := files["backstage/catalog-info.yaml"]; !ok {
		t.Error("expected catalog-info.yaml")
	}

	// Should have one template per catalog entry.
	entries := catalog.All()
	for _, e := range entries {
		path := "backstage/templates/" + e.ID + "/template.yaml"
		if _, ok := files[path]; !ok {
			t.Errorf("expected template file for %s", e.ID)
		}
	}
}

func TestGenerateTemplate_ValidYAML(t *testing.T) {
	entry, ok := catalog.ByID("gcp-gke-cluster")
	if !ok {
		t.Fatal("expected gcp-gke-cluster in catalog")
	}

	yaml := backstage.GenerateTemplate(entry)
	if !strings.Contains(yaml, "apiVersion: scaffolder.backstage.io/v1beta3") {
		t.Error("expected Backstage scaffolder API version")
	}
	if !strings.Contains(yaml, "kind: Template") {
		t.Error("expected kind: Template")
	}
	if !strings.Contains(yaml, entry.ID) {
		t.Error("expected entry ID in template")
	}
	if !strings.Contains(yaml, "bosun:scaffold") {
		t.Error("expected bosun:scaffold action")
	}
}

func TestGenerateTemplate_ContainsSecurityNotes(t *testing.T) {
	entry, ok := catalog.ByID("gcp-gke-cluster")
	if !ok {
		t.Fatal("expected gcp-gke-cluster in catalog")
	}

	yaml := backstage.GenerateTemplate(entry)
	for _, note := range entry.SecurityNotes {
		if !strings.Contains(yaml, note) {
			t.Errorf("expected security note %q in template", note)
		}
	}
}

func TestGenerateCatalogInfo_ListsAllTemplates(t *testing.T) {
	files := backstage.GenerateAll()
	catalogInfo := files["backstage/catalog-info.yaml"]

	for _, e := range catalog.All() {
		if !strings.Contains(catalogInfo, e.ID) {
			t.Errorf("expected catalog-info.yaml to reference %s", e.ID)
		}
	}
}
