package model

import "time"

type ToolKind string

const (
	ToolKindScanner   ToolKind = "scanner"
	ToolKindCollector ToolKind = "collector"
	ToolKindFeed      ToolKind = "feed"
	ToolKindMatcher   ToolKind = "matcher"
)

type ExecutableIdentity struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type DataIdentity struct {
	Version   string    `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
	SHA256    string    `json:"sha256"`
}

type ToolRecord struct {
	ID         string              `json:"id"`
	Name       string              `json:"name"`
	Version    string              `json:"version"`
	Kind       ToolKind            `json:"kind"`
	Origin     string              `json:"origin,omitempty"`
	Executable *ExecutableIdentity `json:"executable,omitempty"`
	Data       *DataIdentity       `json:"data,omitempty"`
}
