// Package workflow renders GitHub Actions workflow YAML from remediation templates.
package workflow

import (
	"embed"
	"fmt"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/stormbane-security/bosun/internal/plan"
)

//go:embed templates/*
var templates embed.FS

// Render produces workflow files for a single remediation.
func Render(r plan.Remediation, vars map[string]string) (map[string]string, error) {
	data := make(map[string]string)
	for k, v := range vars {
		data[k] = v
	}
	for k, v := range r.Params {
		data[k] = v
	}

	tmplPath := filepath.Join("templates", r.Template+".yml.tmpl")
	content, err := templates.ReadFile(tmplPath)
	if err != nil {
		return nil, fmt.Errorf("template %s not found: %w", tmplPath, err)
	}

	t, err := template.New(r.ID).Parse(string(content))
	if err != nil {
		return nil, fmt.Errorf("parsing template: %w", err)
	}

	var buf strings.Builder
	if err := t.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("executing template: %w", err)
	}

	outPath := fmt.Sprintf(".github/workflows/%s.yml", r.ID)
	return map[string]string{outPath: buf.String()}, nil
}
