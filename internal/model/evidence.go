package model

import "time"

type EvidenceKind string

const (
	EvidenceKindCommandOutput EvidenceKind = "command_output"
	EvidenceKindAPIResponse   EvidenceKind = "api_response"
	EvidenceKindFileMetadata  EvidenceKind = "file_metadata"
	EvidenceKindObservation   EvidenceKind = "observation"
)

type ArtifactReference struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	MediaType string `json:"media_type"`
}

type EvidenceRecord struct {
	ID          string             `json:"id"`
	CollectorID string             `json:"collector_id"`
	Kind        EvidenceKind       `json:"kind"`
	ObservedAt  time.Time          `json:"observed_at"`
	Subject     string             `json:"subject"`
	Summary     string             `json:"summary"`
	Command     []string           `json:"command,omitempty"`
	Artifact    *ArtifactReference `json:"artifact,omitempty"`
}
