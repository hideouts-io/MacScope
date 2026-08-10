package model

import "time"

const ScanSchemaVersion = "1"

type RunStatus string

const (
	RunStatusCompleted RunStatus = "completed"
	RunStatusPartial   RunStatus = "partial"
	RunStatusFailed    RunStatus = "failed"
)

type ScannerIdentity struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type HostIdentity struct {
	Hostname     string `json:"hostname"`
	OperatingOS  string `json:"operating_os"`
	Architecture string `json:"architecture"`
	MacOSVersion string `json:"macos_version,omitempty"`
	MacOSBuild   string `json:"macos_build,omitempty"`
	ModelID      string `json:"model_id,omitempty"`
	Chip         string `json:"chip,omitempty"`
}

type PrivilegeEvidence struct {
	Requested                bool   `json:"requested"`
	Granted                  bool   `json:"granted"`
	Collector                string `json:"collector"`
	OrchestratorEffectiveUID int    `json:"orchestrator_effective_uid"`
	CollectorEffectiveUID    *int   `json:"collector_effective_uid,omitempty"`
}

type ScanRun struct {
	SchemaVersion string            `json:"schema_version"`
	RunID         string            `json:"run_id"`
	Scanner       ScannerIdentity   `json:"scanner"`
	Host          HostIdentity      `json:"host"`
	StartedAt     time.Time         `json:"started_at"`
	CompletedAt   time.Time         `json:"completed_at"`
	Status        RunStatus         `json:"status"`
	Privilege     PrivilegeEvidence `json:"privilege"`
	Tools         []ToolRecord      `json:"tools"`
	Coverage      []CoverageRecord  `json:"coverage"`
	Evidence      []EvidenceRecord  `json:"evidence"`
	Findings      []Finding         `json:"findings"`
}
