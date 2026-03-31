// Package generator produces Terraform and GitHub Actions workflow files
// from a remediation plan. It reads embedded templates and renders them
// with the plan's variables and remediation parameters.
package generator

import (
	"bytes"
	"fmt"
	"text/template"

	"github.com/stormbane-security/bosun/internal/generator/terraform"
	"github.com/stormbane-security/bosun/internal/generator/workflow"
	"github.com/stormbane-security/bosun/internal/plan"
)

// Generate produces a map of file paths to their content, ready to be
// written to disk or submitted as a PR.
func Generate(p *plan.Plan) (map[string]string, error) {
	files := make(map[string]string)

	for _, r := range p.Remediations {
		switch r.Kind {
		case "terraform":
			f, err := terraform.Render(r, p.Vars)
			if err != nil {
				return nil, fmt.Errorf("terraform %s: %w", r.ID, err)
			}
			for k, v := range f {
				files[k] = v
			}

		case "workflow":
			f, err := workflow.Render(r, p.Vars)
			if err != nil {
				return nil, fmt.Errorf("workflow %s: %w", r.ID, err)
			}
			for k, v := range f {
				files[k] = v
			}

		case "both":
			tf, err := terraform.Render(r, p.Vars)
			if err != nil {
				return nil, fmt.Errorf("terraform %s: %w", r.ID, err)
			}
			for k, v := range tf {
				files[k] = v
			}

			wf, err := workflow.Render(r, p.Vars)
			if err != nil {
				return nil, fmt.Errorf("workflow %s: %w", r.ID, err)
			}
			for k, v := range wf {
				files[k] = v
			}
		}
	}

	return files, nil
}

// RenderTemplate is a helper that executes a Go text/template with the given data.
func RenderTemplate(tmplStr string, data any) (string, error) {
	t, err := template.New("").Parse(tmplStr)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
