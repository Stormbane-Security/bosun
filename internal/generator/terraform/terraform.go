// Package terraform renders Terraform HCL modules from remediation templates.
package terraform

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

// Render produces Terraform files for a single remediation.
func Render(r plan.Remediation, vars map[string]string) (map[string]string, error) {
	// Merge vars and params for template rendering.
	data := make(map[string]string)
	for k, v := range vars {
		data[k] = v
	}
	for k, v := range r.Params {
		data[k] = v
	}

	tmplPath := filepath.Join("templates", r.Template+".tf.tmpl")
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

	outPath := fmt.Sprintf("terraform/%s.tf", r.ID)
	return map[string]string{outPath: buf.String()}, nil
}
