package model

import "time"

type CoverageArea string

const (
	CoverageAreaHostIdentity              CoverageArea = "host_identity"
	CoverageAreaAppleUpdates              CoverageArea = "apple_updates"
	CoverageAreaSecurityControls          CoverageArea = "security_controls"
	CoverageAreaPersistence               CoverageArea = "persistence"
	CoverageAreaNetworkExposure           CoverageArea = "network_exposure"
	CoverageAreaInstalledSoftware         CoverageArea = "installed_software"
	CoverageAreaDependencyVulnerabilities CoverageArea = "dependency_vulnerabilities"
	CoverageAreaThreatIndicators          CoverageArea = "threat_indicators"
)

type CoverageStatus string

const (
	CoverageStatusComplete   CoverageStatus = "complete"
	CoverageStatusPartial    CoverageStatus = "partial"
	CoverageStatusNotScanned CoverageStatus = "not_scanned"
	CoverageStatusFailed     CoverageStatus = "failed"
)

type CoverageRecord struct {
	ID                string         `json:"id"`
	CollectorID       string         `json:"collector_id"`
	Area              CoverageArea   `json:"area"`
	Target            string         `json:"target"`
	Status            CoverageStatus `json:"status"`
	Reason            string         `json:"reason,omitempty"`
	PrivilegeRequired bool           `json:"privilege_required"`
	StartedAt         time.Time      `json:"started_at"`
	CompletedAt       time.Time      `json:"completed_at"`
}
