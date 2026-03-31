// Package plan defines the remediation plan data model. A Plan is the
// intermediate representation between Beacon findings and generated code.
// It captures what needs to be fixed, which cloud provider and service are
// involved, and shared variables that keep the generated Terraform and
// workflow files coherent with each other.
package plan

// Plan is the top-level remediation plan produced by the matcher and
// consumed by the generator.
type Plan struct {
	// Version of the plan schema.
	Version string `json:"version"`

	// Provider is the cloud provider: "aws" or "gcp".
	Provider string `json:"provider"`

	// Region is the target cloud region (e.g., "us-east-1", "us-central1").
	Region string `json:"region"`

	// Remediations is the ordered list of things to fix.
	Remediations []Remediation `json:"remediations"`

	// Vars are shared variables referenced by both Terraform and workflow
	// templates, ensuring coherence (e.g., the same registry URL appears in
	// both the Terraform Artifact Registry module and the Docker push workflow).
	Vars map[string]string `json:"vars"`
}

// Remediation represents a single security fix to generate.
type Remediation struct {
	// ID is a stable identifier for this remediation (e.g., "gcs-public-bucket").
	ID string `json:"id"`

	// CheckID is the Beacon finding check ID that triggered this remediation.
	CheckID string `json:"check_id"`

	// Kind is the remediation type: "terraform", "workflow", or "both".
	Kind string `json:"kind"`

	// Template is the template name to use (e.g., "gcp/gcs_private", "docker-build-push").
	Template string `json:"template"`

	// Params are template-specific parameters.
	Params map[string]string `json:"params"`

	// Severity from the original finding.
	Severity string `json:"severity"`

	// Description is a human-readable summary of what this remediation does.
	Description string `json:"description"`
}
