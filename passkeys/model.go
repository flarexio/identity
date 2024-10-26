package passkeys

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

type Credential struct {
	ID              string     `json:"id"`
	Name            *string    `json:"name,omitempty"`
	PublicKey       string     `json:"public_key"`
	AttestationType string     `json:"attestation_type"`
	AAGUID          uuid.UUID  `json:"aaguid"`
	LastUsedAt      *time.Time `json:"last_used_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	Transports      []string   `json:"transports"`
	BackupEligible  bool       `json:"backup_eligible"`
	BackupState     bool       `json:"backup_state"`
	IsMFA           bool       `json:"is_mfa"`
}

type TokenResult struct {
	Token string `json:"token"`
}

type FailureResult struct {
	Title   string `json:"title"`
	Details string `json:"details"`
	Status  int    `json:"status"`
}

func (result *FailureResult) Error() string {
	return fmt.Sprintf("status: %d, title: %s, details: %s",
		result.Status, result.Title, result.Details)
}
