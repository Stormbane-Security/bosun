// Package patcher applies generated files to a target repository. It handles
// creating branches, writing files, and preparing changes for PR creation.
package patcher

import (
	"fmt"
	"os"
	"path/filepath"
)

// Apply writes the generated files to the target directory. It creates
// any necessary parent directories and returns the list of paths written.
func Apply(targetDir string, files map[string]string) ([]string, error) {
	var written []string

	for relPath, content := range files {
		fullPath := filepath.Join(targetDir, relPath)

		dir := filepath.Dir(fullPath)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return written, fmt.Errorf("creating directory %s: %w", dir, err)
		}

		if err := os.WriteFile(fullPath, []byte(content), 0o600); err != nil {
			return written, fmt.Errorf("writing %s: %w", fullPath, err)
		}

		written = append(written, relPath)
	}

	return written, nil
}
