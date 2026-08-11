package config

import (
	"fmt"
	"os"
	"path/filepath"
)

const DefaultConfigFilename = "k8s-diagnose.ini"

func DefaultConfigPath() (string, error) {
	return filepath.Abs(DefaultConfigFilename)
}

// ExistingDefaultConfig returns the working-directory configuration when it
// exists. A missing file means built-in defaults; every other filesystem error
// remains visible instead of silently disabling configuration.
func ExistingDefaultConfig() (string, error) {
	path, err := DefaultConfigPath()
	if err != nil {
		return "", fmt.Errorf("既定設定ファイルのパスを解決できません: %w", err)
	}
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("既定設定ファイルを確認できません: %s（%w）", path, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("既定設定ファイルが通常ファイルではありません: %s", path)
	}
	return path, nil
}
