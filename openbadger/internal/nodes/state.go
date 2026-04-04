package nodes

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type State struct {
	NodeID    string `json:"node_id"`
	SiteID    string `json:"site_id"`
	Kind      Kind   `json:"kind"`
	Name      string `json:"name"`
	AuthToken string `json:"auth_token"`
}

func LoadState(path string) (State, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return State{}, fmt.Errorf("state path is required")
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		return State{}, err
	}

	var state State
	if err := json.Unmarshal(contents, &state); err != nil {
		return State{}, fmt.Errorf("decode node state: %w", err)
	}

	state = state.normalized()
	if err := state.Validate(); err != nil {
		return State{}, err
	}

	return state, nil
}

func SaveState(path string, state State) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("state path is required")
	}

	state = state.normalized()
	if err := state.Validate(); err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}

	contents, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode node state: %w", err)
	}
	contents = append(contents, '\n')

	tempFile, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp state file: %w", err)
	}

	tempPath := tempFile.Name()
	defer func() {
		_ = os.Remove(tempPath)
	}()

	if err := tempFile.Chmod(0o600); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("set state file permissions: %w", err)
	}

	if _, err := tempFile.Write(contents); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("write state file: %w", err)
	}

	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("close state file: %w", err)
	}

	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("replace state file: %w", err)
	}

	return nil
}

func (s State) Validate() error {
	if strings.TrimSpace(s.NodeID) == "" {
		return fmt.Errorf("node state node_id is required")
	}

	if strings.TrimSpace(s.SiteID) == "" {
		return fmt.Errorf("node state site_id is required")
	}

	if !ValidateKind(s.Kind) {
		return fmt.Errorf("node state kind %q is invalid", s.Kind)
	}

	if strings.TrimSpace(s.Name) == "" {
		return fmt.Errorf("node state name is required")
	}

	if strings.TrimSpace(s.AuthToken) == "" {
		return fmt.Errorf("node state auth_token is required")
	}

	return nil
}

func (s State) normalized() State {
	s.NodeID = strings.TrimSpace(s.NodeID)
	s.SiteID = strings.TrimSpace(s.SiteID)
	s.Kind = NormalizeKind(string(s.Kind))
	s.Name = strings.TrimSpace(s.Name)
	s.AuthToken = strings.TrimSpace(s.AuthToken)
	return s
}
