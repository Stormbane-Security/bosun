// Package scaffold generates new infrastructure from the Bosun catalog.
// Unlike remediation (which is driven by scan findings), scaffolding is
// driven by user intent — either explicit catalog ID selection or natural
// language mapped to a catalog entry via AI.
package scaffold

import (
	"fmt"
	"strings"

	"github.com/stormbane-security/bosun/pkg/catalog"
	"github.com/stormbane-security/bosun/pkg/generator"
	"github.com/stormbane-security/bosun/pkg/plan"
)

// Request describes what the user wants to scaffold.
type Request struct {
	// CatalogID is the explicit catalog entry to use (if known).
	CatalogID string `json:"catalog_id"`

	// Params are user-supplied parameter values.
	Params map[string]string `json:"params"`
}

// Result contains the generated files and metadata.
type Result struct {
	// Entry is the catalog entry that was used.
	Entry catalog.Entry `json:"entry"`

	// Files maps output file paths to content.
	Files map[string]string `json:"files"`

	// MissingParams lists required params that were not supplied.
	MissingParams []string `json:"missing_params,omitempty"`
}

// Run generates infrastructure from a scaffold request.
func Run(req Request) (*Result, error) {
	entry, ok := catalog.ByID(req.CatalogID)
	if !ok {
		return nil, fmt.Errorf("catalog entry %q not found — run 'bosun catalog' to see available patterns", req.CatalogID)
	}

	// Check for missing required params.
	var missing []string
	for _, p := range entry.Params {
		if p.Required {
			if v, ok := req.Params[p.Name]; !ok || v == "" {
				// Use default if available.
				if p.Default != "" {
					if req.Params == nil {
						req.Params = make(map[string]string)
					}
					req.Params[p.Name] = p.Default
				} else {
					missing = append(missing, p.Name)
				}
			}
		}
	}

	// Fill non-required defaults.
	for _, p := range entry.Params {
		if _, ok := req.Params[p.Name]; !ok && p.Default != "" {
			if req.Params == nil {
				req.Params = make(map[string]string)
			}
			req.Params[p.Name] = p.Default
		}
	}

	if len(missing) > 0 {
		return &Result{
			Entry:         entry,
			MissingParams: missing,
		}, fmt.Errorf("missing required parameters: %s", strings.Join(missing, ", "))
	}

	// Build a plan from the catalog entry's templates.
	p := &plan.Plan{
		Version:  "1",
		Provider: string(entry.Provider),
		Vars:     make(map[string]string),
	}

	for _, tmplRef := range entry.Templates {
		r := plan.Remediation{
			ID:       tmplRef.ID,
			Kind:     tmplRef.Kind,
			Template: tmplRef.Template,
			Params:   req.Params,
		}
		p.Remediations = append(p.Remediations, r)
	}

	// Copy params to plan vars so templates can access them.
	for k, v := range req.Params {
		p.Vars[k] = v
	}

	files, err := generator.Generate(p)
	if err != nil {
		return nil, fmt.Errorf("generating: %w", err)
	}

	return &Result{
		Entry: entry,
		Files: files,
	}, nil
}

// MatchIntent uses keyword matching to find catalog entries that match
// a natural language description. Returns entries sorted by relevance.
// For full AI-powered intent mapping, use the AI package instead.
func MatchIntent(query string) []catalog.Entry {
	query = strings.ToLower(query)
	words := strings.Fields(query)

	type scored struct {
		entry catalog.Entry
		score int
	}

	var results []scored
	for _, entry := range catalog.All() {
		score := 0

		// Match against tags (highest weight).
		for _, tag := range entry.Tags {
			for _, word := range words {
				if strings.Contains(tag, word) || strings.Contains(word, tag) {
					score += 3
				}
			}
		}

		// Match against name.
		nameLower := strings.ToLower(entry.Name)
		for _, word := range words {
			if strings.Contains(nameLower, word) {
				score += 2
			}
		}

		// Match against description.
		descLower := strings.ToLower(entry.Description)
		for _, word := range words {
			if strings.Contains(descLower, word) {
				score++
			}
		}

		// Match against provider.
		for _, word := range words {
			if strings.EqualFold(string(entry.Provider), word) {
				score += 2
			}
		}

		// Match against category.
		for _, word := range words {
			if strings.EqualFold(entry.Category, word) {
				score += 2
			}
		}

		if score > 0 {
			results = append(results, scored{entry: entry, score: score})
		}
	}

	// Sort by score descending.
	for i := 0; i < len(results); i++ {
		for j := i + 1; j < len(results); j++ {
			if results[j].score > results[i].score {
				results[i], results[j] = results[j], results[i]
			}
		}
	}

	entries := make([]catalog.Entry, len(results))
	for i, r := range results {
		entries[i] = r.entry
	}
	return entries
}
