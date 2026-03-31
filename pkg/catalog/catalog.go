// Package catalog defines the available infrastructure patterns that Bosun
// can scaffold. Each entry describes a security-hardened infrastructure
// pattern with its required parameters, the Terraform template it renders,
// and metadata for AI intent mapping and Backstage template generation.
package catalog

import "github.com/stormbane/infra"

// Entry is a scaffoldable infrastructure pattern.
type Entry struct {
	// ID is a unique identifier (e.g., "gcp-gke-cluster").
	ID string `json:"id"`

	// Name is human-readable (e.g., "GKE Kubernetes Cluster").
	Name string `json:"name"`

	// Description explains what this pattern provisions.
	Description string `json:"description"`

	// Provider links to an infra technology ID (e.g., infra.GCP, infra.AWS).
	Provider infra.Technology `json:"provider"`

	// ResourceType links to an infra cloud resource type (e.g., "gcp.gke_cluster").
	// Used by Forecast to map Beacon findings to the correct remediation pattern.
	ResourceType infra.ResourceType `json:"resource_type,omitempty"`

	// Category groups entries: "compute", "storage", "database", "identity",
	// "networking", "cicd", "security".
	Category string `json:"category"`

	// Tags are keywords for AI intent matching.
	Tags []string `json:"tags"`

	// Params are the user-supplied parameters for this pattern.
	Params []Param `json:"params"`

	// Templates lists the Bosun template IDs to render.
	Templates []TemplateRef `json:"templates"`

	// SecurityNotes explains the hardening applied.
	SecurityNotes []string `json:"security_notes"`
}

// Param is a user-supplied parameter for a scaffold.
type Param struct {
	// Name is the parameter key (e.g., "cluster_name").
	Name string `json:"name"`

	// Label is human-readable (e.g., "Cluster Name").
	Label string `json:"label"`

	// Description helps the user understand what to provide.
	Description string `json:"description"`

	// Type: "string", "number", "boolean", "enum".
	Type string `json:"type"`

	// Default value (empty string means required).
	Default string `json:"default,omitempty"`

	// Required means the user must supply this.
	Required bool `json:"required"`

	// Enum lists allowed values when Type is "enum".
	Enum []string `json:"enum,omitempty"`
}

// TemplateRef points to a Bosun template to render.
type TemplateRef struct {
	// Kind: "terraform" or "workflow".
	Kind string `json:"kind"`

	// Template is the Bosun template name (e.g., "gcp/gke_hardened").
	Template string `json:"template"`

	// ID is the remediation ID to use.
	ID string `json:"id"`
}

// All returns the full catalog of available infrastructure patterns.
func All() []Entry {
	return entries
}

// ByProvider returns entries filtered by cloud provider.
func ByProvider(provider infra.Technology) []Entry {
	var result []Entry
	for _, e := range entries {
		if e.Provider == provider {
			result = append(result, e)
		}
	}
	return result
}

// ByResourceType returns the catalog entry that remediates a given cloud resource type.
func ByResourceType(rt infra.ResourceType) (Entry, bool) {
	for _, e := range entries {
		if e.ResourceType == rt {
			return e, true
		}
	}
	return Entry{}, false
}

// ByID returns a single entry by ID.
func ByID(id string) (Entry, bool) {
	for _, e := range entries {
		if e.ID == id {
			return e, true
		}
	}
	return Entry{}, false
}

// ByCategory returns entries filtered by category.
func ByCategory(category string) []Entry {
	var result []Entry
	for _, e := range entries {
		if e.Category == category {
			result = append(result, e)
		}
	}
	return result
}

var entries = []Entry{
	// ── GCP ───────────────────────────────────────────────────────────────
	{
		ID:           "gcp-gke-cluster",
		Name:         "GKE Kubernetes Cluster",
		Description:  "Production-grade GKE cluster with security hardening: private endpoint, workload identity, shielded nodes, network policy, and binary authorization.",
		Provider:     infra.GCP,
		ResourceType: "gcp.gke_cluster",
		Category:     "compute",
		Tags:        []string{"kubernetes", "k8s", "gke", "cluster", "containers", "gcp"},
		Params: []Param{
			{Name: "cluster_name", Label: "Cluster Name", Type: "string", Required: true},
			{Name: "project_id", Label: "GCP Project ID", Type: "string", Required: true},
			{Name: "region", Label: "Region", Type: "string", Default: "us-central1", Required: true},
			{Name: "node_count", Label: "Initial Node Count", Type: "number", Default: "3"},
			{Name: "machine_type", Label: "Machine Type", Type: "string", Default: "e2-standard-4"},
			{Name: "environment", Label: "Environment", Type: "enum", Default: "production", Enum: []string{"production", "staging", "development"}},
		},
		Templates: []TemplateRef{
			{Kind: "terraform", Template: "gcp/gke_hardened", ID: "gke-hardened"},
		},
		SecurityNotes: []string{
			"Private cluster endpoint (no public API server)",
			"Workload Identity enabled (no node service account key export)",
			"Shielded GKE nodes with secure boot",
			"Network policy enforcement via Calico",
			"Binary authorization for container image verification",
			"Uses terraform-google-modules/kubernetes-engine safer-cluster",
		},
	},
	{
		ID:           "gcp-cloudsql",
		Name:         "Cloud SQL Database",
		Description:  "Private Cloud SQL PostgreSQL instance with automated backups, SSL enforcement, and no public IP.",
		Provider:     infra.GCP,
		ResourceType: "gcp.cloudsql_instance",
		Category:     "database",
		Tags:        []string{"database", "postgres", "postgresql", "sql", "cloudsql", "gcp"},
		Params: []Param{
			{Name: "instance_name", Label: "Instance Name", Type: "string", Required: true},
			{Name: "project_id", Label: "GCP Project ID", Type: "string", Required: true},
			{Name: "region", Label: "Region", Type: "string", Default: "us-central1", Required: true},
			{Name: "tier", Label: "Machine Tier", Type: "string", Default: "db-f1-micro"},
			{Name: "database_version", Label: "Database Version", Type: "string", Default: "POSTGRES_15"},
		},
		Templates: []TemplateRef{
			{Kind: "terraform", Template: "gcp/cloudsql_private", ID: "cloudsql-private"},
		},
		SecurityNotes: []string{
			"No public IP assigned",
			"SSL/TLS required for all connections",
			"Automated daily backups with point-in-time recovery",
			"Private service networking via VPC peering",
			"Uses terraform-google-modules/sql-db",
		},
	},
	{
		ID:           "gcp-gcs-bucket",
		Name:         "GCS Storage Bucket",
		Description:  "Private GCS bucket with uniform bucket-level access, versioning, and encryption.",
		Provider:     infra.GCP,
		ResourceType: "gcp.storage_bucket",
		Category:     "storage",
		Tags:        []string{"storage", "bucket", "gcs", "blob", "object", "gcp"},
		Params: []Param{
			{Name: "bucket_name", Label: "Bucket Name", Type: "string", Required: true},
			{Name: "project_id", Label: "GCP Project ID", Type: "string", Required: true},
			{Name: "location", Label: "Location", Type: "string", Default: "US"},
		},
		Templates: []TemplateRef{
			{Kind: "terraform", Template: "gcp/gcs_private", ID: "gcs-private"},
		},
		SecurityNotes: []string{
			"Public access blocked",
			"Uniform bucket-level access enforced",
			"Object versioning enabled",
			"Google-managed encryption at rest",
		},
	},
	{
		ID:           "gcp-iam-baseline",
		Name:         "GCP IAM Baseline",
		Description:  "Replace primitive IAM roles (Owner/Editor/Viewer) with least-privilege predefined roles.",
		Provider:     infra.GCP,
		ResourceType: "gcp.iam_binding",
		Category:     "identity",
		Tags:        []string{"iam", "identity", "roles", "permissions", "least-privilege", "gcp"},
		Params: []Param{
			{Name: "project_id", Label: "GCP Project ID", Type: "string", Required: true},
		},
		Templates: []TemplateRef{
			{Kind: "terraform", Template: "gcp/iam_least_privilege", ID: "gcp-iam-least-privilege"},
		},
		SecurityNotes: []string{
			"Removes primitive roles (roles/owner, roles/editor)",
			"Assigns predefined roles scoped to specific services",
			"Follows principle of least privilege",
		},
	},

	// ── AWS ───────────────────────────────────────────────────────────────
	{
		ID:           "aws-eks-cluster",
		Name:         "EKS Kubernetes Cluster",
		Description:  "Production EKS cluster with private endpoint, managed node groups, envelope encryption, and IRSA.",
		Provider:     infra.AWS,
		ResourceType: "aws.eks_cluster",
		Category:     "compute",
		Tags:        []string{"kubernetes", "k8s", "eks", "cluster", "containers", "aws"},
		Params: []Param{
			{Name: "cluster_name", Label: "Cluster Name", Type: "string", Required: true},
			{Name: "region", Label: "AWS Region", Type: "string", Default: "us-east-1", Required: true},
			{Name: "vpc_id", Label: "VPC ID", Type: "string", Required: true},
			{Name: "subnet_ids", Label: "Subnet IDs (comma-separated)", Type: "string", Required: true},
			{Name: "node_instance_type", Label: "Node Instance Type", Type: "string", Default: "m5.large"},
			{Name: "desired_size", Label: "Desired Node Count", Type: "number", Default: "3"},
		},
		Templates: []TemplateRef{
			{Kind: "terraform", Template: "aws/eks_private", ID: "eks-private"},
		},
		SecurityNotes: []string{
			"Private API server endpoint",
			"Envelope encryption for Kubernetes secrets",
			"IRSA (IAM Roles for Service Accounts) enabled",
			"Managed node groups with latest AMI",
			"Uses terraform-aws-modules/eks",
		},
	},
	{
		ID:           "aws-s3-bucket",
		Name:         "S3 Storage Bucket",
		Description:  "Private S3 bucket with public access block, versioning, encryption, and access logging.",
		Provider:     infra.AWS,
		ResourceType: "aws.s3_bucket",
		Category:     "storage",
		Tags:        []string{"storage", "bucket", "s3", "blob", "object", "aws"},
		Params: []Param{
			{Name: "bucket_name", Label: "Bucket Name", Type: "string", Required: true},
			{Name: "region", Label: "AWS Region", Type: "string", Default: "us-east-1"},
		},
		Templates: []TemplateRef{
			{Kind: "terraform", Template: "aws/s3_private", ID: "s3-private"},
		},
		SecurityNotes: []string{
			"Public access block on all four settings",
			"AES-256 server-side encryption",
			"Object versioning enabled",
			"Access logging enabled",
			"Uses terraform-aws-modules/s3-bucket",
		},
	},
	{
		ID:           "aws-ec2-security-group",
		Name:         "EC2 Security Group",
		Description:  "Restrictive security group that blocks 0.0.0.0/0 ingress, allows only specified CIDR ranges.",
		Provider:     infra.AWS,
		ResourceType: "aws.ec2_security_group",
		Category:     "networking",
		Tags:        []string{"ec2", "security-group", "firewall", "networking", "aws"},
		Params: []Param{
			{Name: "vpc_id", Label: "VPC ID", Type: "string", Required: true},
			{Name: "name", Label: "Security Group Name", Type: "string", Required: true},
			{Name: "allowed_cidr", Label: "Allowed CIDR (e.g., 10.0.0.0/8)", Type: "string", Default: "10.0.0.0/8"},
		},
		Templates: []TemplateRef{
			{Kind: "terraform", Template: "aws/ec2_security_group", ID: "ec2-private"},
		},
		SecurityNotes: []string{
			"No 0.0.0.0/0 ingress rules",
			"Explicit deny-all default",
			"CIDR-restricted ingress only",
		},
	},
	{
		ID:           "aws-iam-mfa",
		Name:         "AWS IAM MFA Policy",
		Description:  "Enforce MFA for all IAM users via an IAM policy condition.",
		Provider:     infra.AWS,
		ResourceType: "aws.iam_policy",
		Category:     "identity",
		Tags:        []string{"iam", "mfa", "identity", "authentication", "aws"},
		Params: []Param{},
		Templates: []TemplateRef{
			{Kind: "terraform", Template: "aws/iam_mfa_policy", ID: "aws-iam-mfa"},
		},
		SecurityNotes: []string{
			"Denies all actions unless MFA is present",
			"Allows users to manage their own MFA devices",
		},
	},

	// ── Okta ──────────────────────────────────────────────────────────────
	{
		ID:          "okta-org-baseline",
		Name:        "Okta Organization Baseline",
		Description: "Full Okta hardening: MFA policy, password policy, session timeouts, ThreatInsight, and department-based groups.",
		Provider:    infra.Okta,
		Category:    "identity",
		Tags:        []string{"okta", "iam", "identity", "sso", "mfa", "password", "groups", "baseline"},
		Params: []Param{
			{Name: "org_name", Label: "Okta Org Name", Type: "string", Required: true},
			{Name: "departments", Label: "Departments (comma-separated)", Type: "string", Default: "engineering,product,security,operations"},
		},
		Templates: []TemplateRef{
			{Kind: "terraform", Template: "okta/mfa_policy", ID: "okta-mfa"},
			{Kind: "terraform", Template: "okta/password_policy", ID: "okta-password"},
			{Kind: "terraform", Template: "okta/session_policy", ID: "okta-session"},
			{Kind: "terraform", Template: "okta/threat_insight", ID: "okta-threat-insight"},
			{Kind: "terraform", Template: "okta/groups", ID: "okta-groups"},
		},
		SecurityNotes: []string{
			"Phishing-resistant MFA (Okta Verify + WebAuthn), SMS/call disabled",
			"NIST 800-63B password policy: 14 char min, no composition rules",
			"1-hour idle timeout, 12-hour max session lifetime",
			"ThreatInsight in block mode",
			"Department-based groups with automatic membership rules",
		},
	},
	{
		ID:          "okta-mfa",
		Name:        "Okta MFA Policy",
		Description: "Enforce phishing-resistant MFA for all Okta users.",
		Provider:    infra.Okta,
		Category:    "identity",
		Tags:        []string{"okta", "mfa", "authentication", "phishing"},
		Params:      []Param{},
		Templates: []TemplateRef{
			{Kind: "terraform", Template: "okta/mfa_policy", ID: "okta-mfa"},
		},
		SecurityNotes: []string{
			"Okta Verify and WebAuthn required",
			"SMS, voice call, and security question disabled",
		},
	},

	// ── CI/CD ─────────────────────────────────────────────────────────────
	{
		ID:          "cicd-secure-docker",
		Name:        "Secure Docker Build Pipeline",
		Description: "GitHub Actions workflow for building, signing, and scanning container images with SBOM generation.",
		Provider:    "github-actions",
		Category:    "cicd",
		Tags:        []string{"docker", "container", "cicd", "pipeline", "sbom", "signing", "cosign", "trivy"},
		Params: []Param{
			{Name: "image_name", Label: "Image Name", Type: "string", Required: true},
			{Name: "registry", Label: "Container Registry", Type: "string", Default: "ghcr.io"},
		},
		Templates: []TemplateRef{
			{Kind: "workflow", Template: "docker-build-push", ID: "supply-chain-docker"},
		},
		SecurityNotes: []string{
			"All actions SHA-pinned",
			"Container image signing with cosign",
			"SBOM generation with anchore/sbom-action",
			"Vulnerability scanning with trivy",
			"StepSecurity harden-runner (egress audit)",
			"Minimal GITHUB_TOKEN permissions",
		},
	},
	{
		ID:          "cicd-go-ci",
		Name:        "Go CI Pipeline",
		Description: "GitHub Actions workflow for Go projects with linting, testing, and security scanning.",
		Provider:    "github-actions",
		Category:    "cicd",
		Tags:        []string{"go", "golang", "ci", "cicd", "testing", "lint"},
		Params:      []Param{},
		Templates: []TemplateRef{
			{Kind: "workflow", Template: "go-ci", ID: "go-ci"},
		},
		SecurityNotes: []string{
			"All actions SHA-pinned",
			"StepSecurity harden-runner",
			"gosec security scanner",
			"Minimal GITHUB_TOKEN permissions",
		},
	},
	{
		ID:          "cicd-terraform-ci",
		Name:        "Terraform CI Pipeline",
		Description: "GitHub Actions workflow for Terraform with fmt, validate, plan, and security scanning.",
		Provider:    "github-actions",
		Category:    "cicd",
		Tags:        []string{"terraform", "ci", "cicd", "infrastructure", "iac"},
		Params:      []Param{},
		Templates: []TemplateRef{
			{Kind: "workflow", Template: "terraform-ci", ID: "terraform-ci"},
		},
		SecurityNotes: []string{
			"All actions SHA-pinned",
			"tfsec security scanning",
			"checkov policy scanning",
			"Plan output as PR comment",
			"Minimal GITHUB_TOKEN permissions",
		},
	},
	{
		ID:          "cicd-beacon-scan",
		Name:        "Beacon Scheduled Scan",
		Description: "GitHub Actions workflow that runs Beacon scans on a schedule and opens issues for new findings.",
		Provider:    "github-actions",
		Category:    "cicd",
		Tags:        []string{"beacon", "scan", "security", "monitoring", "cicd", "scheduled"},
		Params: []Param{
			{Name: "target_domain", Label: "Target Domain", Type: "string", Required: true},
			{Name: "schedule", Label: "Cron Schedule", Type: "string", Default: "0 6 * * 1"},
		},
		Templates: []TemplateRef{
			{Kind: "workflow", Template: "beacon-scan", ID: "beacon-scan"},
		},
		SecurityNotes: []string{
			"All actions SHA-pinned",
			"Scheduled surface-only scans (safe, no active probing)",
			"Findings stored as artifacts",
		},
	},
}
