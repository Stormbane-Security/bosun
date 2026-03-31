// Package tracer maps cloud resources back to the GitHub repositories
// that deploy to them. Given a cloud resource identifier (GKE cluster,
// EC2 instance, S3 bucket, etc.), it searches GitHub for repos containing
// deployment configurations that reference that resource.
//
// Detection methods:
//  1. GitHub Actions workflows: search for deploy steps referencing the resource
//  2. Terraform state: search for .tf files referencing the resource
//  3. Kubernetes manifests: search for deployment configs targeting the cluster
//  4. Docker Compose / Helm charts: search for image references
package tracer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Link represents a traced connection between a cloud resource and a
// GitHub repository that deploys to it.
type Link struct {
	// Resource is the cloud resource identifier (e.g., "gke/my-cluster",
	// "s3/my-bucket", "ec2/i-1234567890abcdef0").
	Resource string `json:"resource"`

	// Repo is the GitHub repository (owner/name).
	Repo string `json:"repo"`

	// FilePath is the file in the repo that references the resource.
	FilePath string `json:"file_path"`

	// LineNumber is the line in the file where the reference was found.
	LineNumber int `json:"line_number,omitempty"`

	// Method is how the link was discovered: "workflow", "terraform",
	// "kubernetes", "dockerfile", "helm".
	Method string `json:"method"`

	// Confidence is how certain we are of the link: "high", "medium", "low".
	Confidence string `json:"confidence"`

	// Snippet is a code excerpt showing the reference.
	Snippet string `json:"snippet,omitempty"`
}

// Tracer searches GitHub for repositories that deploy to a given cloud resource.
type Tracer struct {
	token   string
	baseURL string
	client  *http.Client
}

// New creates a Tracer. The token should be a GitHub PAT or App installation token
// with repo read access across the organization.
func New(token string) *Tracer {
	return &Tracer{
		token:   token,
		baseURL: "https://api.github.com",
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

// SetBaseURL overrides the API base URL (for testing).
func (t *Tracer) SetBaseURL(url string) {
	t.baseURL = strings.TrimSuffix(url, "/")
}

// Trace searches for repos that deploy to the given cloud resource within
// the specified GitHub organization.
func (t *Tracer) Trace(ctx context.Context, org string, resource Resource) ([]Link, error) {
	var links []Link

	// Build search queries for each detection method.
	queries := buildQueries(org, resource)

	for _, q := range queries {
		if ctx.Err() != nil {
			break
		}

		results, err := t.searchCode(ctx, q.query)
		if err != nil {
			continue // best-effort
		}

		for _, r := range results {
			links = append(links, Link{
				Resource:   resource.String(),
				Repo:       r.repo,
				FilePath:   r.path,
				Method:     q.method,
				Confidence: q.confidence,
				Snippet:    r.snippet,
			})
		}
	}

	return dedup(links), nil
}

// Resource identifies a cloud resource to trace back to source code.
type Resource struct {
	// Provider: "gcp", "aws", "azure"
	Provider string `json:"provider"`

	// Service: "gke", "ec2", "s3", "ecs", "cloud_run", etc.
	Service string `json:"service"`

	// Name is the resource name or identifier.
	Name string `json:"name"`

	// Region is the resource's region.
	Region string `json:"region,omitempty"`

	// Project is the GCP project or AWS account.
	Project string `json:"project,omitempty"`
}

func (r Resource) String() string {
	return fmt.Sprintf("%s/%s/%s", r.Provider, r.Service, r.Name)
}

type searchQuery struct {
	query      string
	method     string
	confidence string
}

func buildQueries(org string, r Resource) []searchQuery {
	var queries []searchQuery

	switch r.Service {
	case "gke":
		// GitHub Actions deploying to GKE cluster.
		queries = append(queries, searchQuery{
			query:      fmt.Sprintf("org:%s %s path:.github/workflows", org, r.Name),
			method:     "workflow",
			confidence: "high",
		})
		// Terraform referencing GKE cluster.
		queries = append(queries, searchQuery{
			query:      fmt.Sprintf("org:%s %s extension:tf", org, r.Name),
			method:     "terraform",
			confidence: "high",
		})
		// Kubernetes manifests targeting the cluster.
		queries = append(queries, searchQuery{
			query:      fmt.Sprintf("org:%s %s path:k8s OR path:kubernetes OR path:deploy", org, r.Name),
			method:     "kubernetes",
			confidence: "medium",
		})

	case "eks":
		queries = append(queries, searchQuery{
			query:      fmt.Sprintf("org:%s %s path:.github/workflows", org, r.Name),
			method:     "workflow",
			confidence: "high",
		})
		queries = append(queries, searchQuery{
			query:      fmt.Sprintf("org:%s %s extension:tf", org, r.Name),
			method:     "terraform",
			confidence: "high",
		})

	case "s3":
		queries = append(queries, searchQuery{
			query:      fmt.Sprintf("org:%s %s extension:tf", org, r.Name),
			method:     "terraform",
			confidence: "high",
		})
		// S3 deploy in workflows.
		queries = append(queries, searchQuery{
			query:      fmt.Sprintf("org:%s %s s3 sync path:.github/workflows", org, r.Name),
			method:     "workflow",
			confidence: "medium",
		})

	case "ec2":
		queries = append(queries, searchQuery{
			query:      fmt.Sprintf("org:%s %s extension:tf", org, r.Name),
			method:     "terraform",
			confidence: "high",
		})

	case "cloud_run", "cloudrun":
		queries = append(queries, searchQuery{
			query:      fmt.Sprintf("org:%s %s path:.github/workflows", org, r.Name),
			method:     "workflow",
			confidence: "high",
		})
		queries = append(queries, searchQuery{
			query:      fmt.Sprintf("org:%s %s extension:tf", org, r.Name),
			method:     "terraform",
			confidence: "high",
		})

	default:
		// Generic search.
		queries = append(queries, searchQuery{
			query:      fmt.Sprintf("org:%s %s extension:tf", org, r.Name),
			method:     "terraform",
			confidence: "medium",
		})
		queries = append(queries, searchQuery{
			query:      fmt.Sprintf("org:%s %s path:.github/workflows", org, r.Name),
			method:     "workflow",
			confidence: "medium",
		})
	}

	return queries
}

type searchResult struct {
	repo    string
	path    string
	snippet string
}

func (t *Tracer) searchCode(ctx context.Context, query string) ([]searchResult, error) {
	u := fmt.Sprintf("%s/search/code?q=%s&per_page=10", t.baseURL, url.QueryEscape(query))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+t.token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub search %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Items []struct {
			Name       string `json:"name"`
			Path       string `json:"path"`
			Repository struct {
				FullName string `json:"full_name"`
			} `json:"repository"`
			TextMatches []struct {
				Fragment string `json:"fragment"`
			} `json:"text_matches"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var results []searchResult
	for _, item := range result.Items {
		snippet := ""
		if len(item.TextMatches) > 0 {
			snippet = item.TextMatches[0].Fragment
		}
		results = append(results, searchResult{
			repo:    item.Repository.FullName,
			path:    item.Path,
			snippet: snippet,
		})
	}

	return results, nil
}

func dedup(links []Link) []Link {
	seen := make(map[string]bool)
	var result []Link
	for _, l := range links {
		key := l.Repo + ":" + l.FilePath + ":" + l.Method
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, l)
	}
	return result
}
