package tracer_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stormbane-security/bosun/internal/tracer"
)

func TestTrace_GKECluster(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"items": []map[string]any{
				{
					"name": "deploy.yml",
					"path": ".github/workflows/deploy.yml",
					"repository": map[string]string{
						"full_name": "myorg/myapp",
					},
					"text_matches": []map[string]string{
						{"fragment": "cluster: prod-gke"},
					},
				},
			},
		})
	}))
	defer srv.Close()

	tr := tracer.New("test-token")
	tr.SetBaseURL(srv.URL)

	links, err := tr.Trace(context.Background(), "myorg", tracer.Resource{
		Provider: "gcp",
		Service:  "gke",
		Name:     "prod-gke",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(links) == 0 {
		t.Fatal("expected at least one link")
	}
	if links[0].Repo != "myorg/myapp" {
		t.Errorf("expected repo 'myorg/myapp', got %q", links[0].Repo)
	}
	if links[0].Method != "workflow" {
		t.Errorf("expected method 'workflow', got %q", links[0].Method)
	}
}

func TestTrace_NoResults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"items": []any{}})
	}))
	defer srv.Close()

	tr := tracer.New("test-token")
	tr.SetBaseURL(srv.URL)

	links, err := tr.Trace(context.Background(), "myorg", tracer.Resource{
		Provider: "aws",
		Service:  "s3",
		Name:     "nonexistent-bucket",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(links) != 0 {
		t.Errorf("expected 0 links, got %d", len(links))
	}
}

func TestTrace_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"items": []any{}})
	}))
	defer srv.Close()

	tr := tracer.New("test-token")
	tr.SetBaseURL(srv.URL)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	links, err := tr.Trace(ctx, "myorg", tracer.Resource{
		Provider: "gcp",
		Service:  "gke",
		Name:     "cluster",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(links) != 0 {
		t.Errorf("expected 0 links for cancelled context, got %d", len(links))
	}
}

func TestTrace_Deduplication(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		// Return the same result from multiple queries.
		json.NewEncoder(w).Encode(map[string]any{
			"items": []map[string]any{
				{
					"name": "main.tf",
					"path": "infra/main.tf",
					"repository": map[string]string{
						"full_name": "myorg/infra",
					},
				},
			},
		})
	}))
	defer srv.Close()

	tr := tracer.New("test-token")
	tr.SetBaseURL(srv.URL)

	links, err := tr.Trace(context.Background(), "myorg", tracer.Resource{
		Provider: "gcp",
		Service:  "gke",
		Name:     "cluster",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// GKE queries 3 search APIs (workflow, terraform, kubernetes) but results should be deduped.
	if callCount < 2 {
		t.Errorf("expected multiple API calls for GKE, got %d", callCount)
	}

	// Same repo+path+method should be deduped, but different methods should not.
	for i, l := range links {
		for j, l2 := range links {
			if i != j && l.Repo == l2.Repo && l.FilePath == l2.FilePath && l.Method == l2.Method {
				t.Errorf("duplicate link found: %+v", l)
			}
		}
	}
}

func TestResource_String(t *testing.T) {
	r := tracer.Resource{Provider: "gcp", Service: "gke", Name: "prod"}
	if s := r.String(); s != "gcp/gke/prod" {
		t.Errorf("expected 'gcp/gke/prod', got %q", s)
	}
}
