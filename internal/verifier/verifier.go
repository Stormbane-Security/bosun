// Package verifier confirms that a remediation PR was deployed and the
// original finding is resolved. It closes the loop:
//
//	Beacon scan → Bosun PR → merge → deploy → Beacon rescan → verify
//
// Verification methods:
//  1. Webhook: listen for GitHub deployment_status events
//  2. Poll: check GitHub Actions workflow status after merge
//  3. Rescan: trigger a targeted Beacon scan of the specific asset/check
package verifier

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Verification represents the status of a remediation verification.
type Verification struct {
	// RemediationID is the Bosun remediation that was applied.
	RemediationID string `json:"remediation_id"`

	// PRURL is the GitHub PR that was merged.
	PRURL string `json:"pr_url"`

	// Asset is the Beacon asset to verify.
	Asset string `json:"asset"`

	// CheckID is the Beacon check ID to verify is resolved.
	CheckID string `json:"check_id"`

	// Status: "pending", "deployed", "verified", "failed".
	Status string `json:"status"`

	// DeployedAt is when the fix was deployed (from deployment_status event).
	DeployedAt *time.Time `json:"deployed_at,omitempty"`

	// VerifiedAt is when Beacon confirmed the finding is resolved.
	VerifiedAt *time.Time `json:"verified_at,omitempty"`

	// Notes contains any verification messages.
	Notes string `json:"notes,omitempty"`
}

// Verifier tracks remediation PRs through deployment and verification.
type Verifier struct {
	ghToken    string
	beaconURL  string
	baseURL    string
	client     *http.Client
	pending    map[string]*Verification // key: PR URL
}

// New creates a Verifier.
func New(githubToken, beaconURL string) *Verifier {
	return &Verifier{
		ghToken:   githubToken,
		beaconURL: strings.TrimSuffix(beaconURL, "/"),
		baseURL:   "https://api.github.com",
		client:    &http.Client{Timeout: 30 * time.Second},
		pending:   make(map[string]*Verification),
	}
}

// SetBaseURL overrides the GitHub API URL (for testing).
func (v *Verifier) SetBaseURL(url string) {
	v.baseURL = strings.TrimSuffix(url, "/")
}

// Track begins tracking a remediation PR for deployment and verification.
func (v *Verifier) Track(verification Verification) {
	verification.Status = "pending"
	v.pending[verification.PRURL] = &verification
}

// CheckDeployment polls GitHub to see if the PR's branch has been deployed.
func (v *Verifier) CheckDeployment(ctx context.Context, prURL string) (*Verification, error) {
	ver, ok := v.pending[prURL]
	if !ok {
		return nil, fmt.Errorf("PR %s is not being tracked", prURL)
	}

	// Parse owner/repo and PR number from URL.
	owner, repo, prNum, err := parsePRURL(prURL)
	if err != nil {
		return ver, err
	}

	// Check if PR is merged.
	merged, err := v.isPRMerged(ctx, owner, repo, prNum)
	if err != nil {
		return ver, err
	}
	if !merged {
		ver.Notes = "PR not yet merged"
		return ver, nil
	}

	// Check if the merge commit's workflow succeeded.
	success, err := v.isWorkflowSuccess(ctx, owner, repo, prNum)
	if err != nil {
		return ver, err
	}

	if success {
		now := time.Now()
		ver.Status = "deployed"
		ver.DeployedAt = &now
		ver.Notes = "CI/CD workflow passed after merge"
	} else {
		ver.Notes = "Waiting for CI/CD workflow to complete"
	}

	return ver, nil
}

// TriggerRescan asks Beacon to rescan a specific asset and check.
// Returns true if the finding is no longer present (remediation verified).
func (v *Verifier) TriggerRescan(ctx context.Context, prURL string) (*Verification, error) {
	ver, ok := v.pending[prURL]
	if !ok {
		return nil, fmt.Errorf("PR %s is not being tracked", prURL)
	}

	if ver.Status != "deployed" {
		return ver, fmt.Errorf("cannot rescan — PR not yet deployed (status: %s)", ver.Status)
	}

	if v.beaconURL == "" {
		ver.Notes = "No Beacon URL configured — manual verification required"
		return ver, nil
	}

	// Call Beacon's API to trigger a targeted scan.
	scanURL := fmt.Sprintf("%s/api/v1/scan", v.beaconURL)
	payload := fmt.Sprintf(`{"targets":["%s"],"checks":["%s"]}`, ver.Asset, ver.CheckID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, scanURL, strings.NewReader(payload))
	if err != nil {
		return ver, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := v.client.Do(req)
	if err != nil {
		ver.Notes = fmt.Sprintf("Beacon rescan failed: %v", err)
		return ver, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		ver.Notes = fmt.Sprintf("Beacon rescan returned %d: %s", resp.StatusCode, body)
		return ver, nil
	}

	var result struct {
		Findings []struct {
			CheckID string `json:"check_id"`
		} `json:"findings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		ver.Notes = "Rescan completed but could not parse results"
		return ver, nil
	}

	// Check if the original finding is still present.
	findingPresent := false
	for _, f := range result.Findings {
		if f.CheckID == ver.CheckID {
			findingPresent = true
			break
		}
	}

	if !findingPresent {
		now := time.Now()
		ver.Status = "verified"
		ver.VerifiedAt = &now
		ver.Notes = "Beacon rescan confirmed finding is resolved"
	} else {
		ver.Status = "failed"
		ver.Notes = "Beacon rescan found the issue is still present"
	}

	return ver, nil
}

// Pending returns all verifications that are not yet complete.
func (v *Verifier) Pending() []*Verification {
	var result []*Verification
	for _, ver := range v.pending {
		if ver.Status == "pending" || ver.Status == "deployed" {
			result = append(result, ver)
		}
	}
	return result
}

func parsePRURL(prURL string) (owner, repo, number string, err error) {
	// https://github.com/owner/repo/pull/123
	parts := strings.Split(strings.TrimPrefix(prURL, "https://github.com/"), "/")
	if len(parts) < 4 || parts[2] != "pull" {
		return "", "", "", fmt.Errorf("invalid PR URL: %s", prURL)
	}
	return parts[0], parts[1], parts[3], nil
}

func (v *Verifier) isPRMerged(ctx context.Context, owner, repo, prNum string) (bool, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/pulls/%s", v.baseURL, owner, repo, prNum)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+v.ghToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := v.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var pr struct {
		Merged bool `json:"merged"`
	}
	json.NewDecoder(resp.Body).Decode(&pr)
	return pr.Merged, nil
}

func (v *Verifier) isWorkflowSuccess(ctx context.Context, owner, repo, prNum string) (bool, error) {
	// Get the PR's merge commit SHA first.
	url := fmt.Sprintf("%s/repos/%s/%s/pulls/%s", v.baseURL, owner, repo, prNum)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+v.ghToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := v.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var pr struct {
		MergeCommitSHA string `json:"merge_commit_sha"`
	}
	json.NewDecoder(resp.Body).Decode(&pr)

	if pr.MergeCommitSHA == "" {
		return false, nil
	}

	// Check the commit's status.
	statusURL := fmt.Sprintf("%s/repos/%s/%s/commits/%s/status", v.baseURL, owner, repo, pr.MergeCommitSHA)
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, statusURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+v.ghToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err = v.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var status struct {
		State string `json:"state"`
	}
	json.NewDecoder(resp.Body).Decode(&status)

	return status.State == "success", nil
}
