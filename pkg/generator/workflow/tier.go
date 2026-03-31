package workflow

// Tier controls which security features are enabled in generated workflows.
type Tier string

const (
	// TierFree generates workflows using only free-tier features:
	//   - StepSecurity harden-runner (audit mode)
	//   - Cosign keyless signing (Sigstore)
	//   - Anchore SBOM generation
	//   - Trivy vulnerability scanning
	//   - Artifact upload for scan results
	TierFree Tier = "free"

	// TierPaid generates workflows with configurable paid features.
	// Each paid feature is independently toggleable via PaidOptions.
	TierPaid Tier = "paid"
)

// PaidOptions controls which paid features to enable in TierPaid workflows.
// Each field is independent — enable only what you're paying for.
type PaidOptions struct {
	// StepSecurityBlock enables harden-runner in "block" mode instead of
	// "audit" mode. Requires StepSecurity paid plan.
	StepSecurityBlock bool `json:"stepsecurity_block"`

	// GHAS enables GitHub Advanced Security features: SARIF upload to
	// Security tab, CodeQL scanning, dependency review enforcement.
	// Free for public repos. Requires GHAS license for private repos.
	GHAS bool `json:"ghas"`

	// DependencyReview enables the dependency-review-action to block PRs
	// that introduce known-vulnerable dependencies. Free for public repos,
	// requires GHAS for private repos.
	DependencyReview bool `json:"dependency_review"`

	// CodeQL enables CodeQL static analysis. Free for public repos,
	// requires GHAS for private repos.
	CodeQL bool `json:"codeql"`
}
