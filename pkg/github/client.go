// Package github provides GitHub API operations for Bosun, including
// branch creation, file commits, and pull request management.
// Designed to work with both personal access tokens and GitHub App
// installation tokens.
package github

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Client wraps GitHub API operations needed by Bosun.
type Client struct {
	httpClient *http.Client
	token      string
	baseURL    string
}

// New creates a GitHub API client. The token can be a PAT or a
// GitHub App installation token.
func New(token string) *Client {
	return &Client{
		httpClient: http.DefaultClient,
		token:      token,
		baseURL:    "https://api.github.com",
	}
}

// SetBaseURL overrides the API base URL (for testing).
func (c *Client) SetBaseURL(url string) {
	c.baseURL = url
}

// CreatePR creates a pull request and returns the PR URL.
func (c *Client) CreatePR(owner, repo, title, body, head, base string) (string, error) {
	payload := map[string]string{
		"title": title,
		"body":  body,
		"head":  head,
		"base":  base,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("%s/repos/%s/%s/pulls", c.baseURL, owner, repo)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("creating PR: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("GitHub API %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		HTMLURL string `json:"html_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.HTMLURL, nil
}
