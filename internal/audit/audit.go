// Package audit records security-sensitive operations.
//
// The record shape is the minimum required by DESIGN.md §19: actor, action,
// resource, resource id, timestamp and result. Secrets are never written; the
// caller is responsible for redacting free-text detail, and helpers here make
// that the easy path.
package audit

import (
	"fmt"
	"strings"
	"time"
)

// Action is a canonical audited operation.
type Action string

const (
	ActionLoginSuccess          Action = "LOGIN_SUCCESS"
	ActionLoginFailure          Action = "LOGIN_FAILURE"
	ActionLogout                Action = "LOGOUT"
	ActionSessionRevoked        Action = "SESSION_REVOKED"
	ActionAgentEnrolled         Action = "AGENT_ENROLLED"
	ActionAgentTokenIssued      Action = "AGENT_TOKEN_ISSUED"
	ActionAgentTokenRotated     Action = "AGENT_TOKEN_ROTATED"
	ActionAgentTokenRevoked     Action = "AGENT_TOKEN_REVOKED"
	ActionAgentHeartbeat        Action = "AGENT_HEARTBEAT"
	ActionRuleLoaded            Action = "RULE_LOADED"
	ActionRuleLoadFailed        Action = "RULE_LOAD_FAILED"
	ActionRuleSaved             Action = "RULE_SAVED"
	ActionRuleDeleted           Action = "RULE_DELETED"
	ActionAlertStatusChanged    Action = "ALERT_STATUS_CHANGED"
	ActionIncidentStatusChanged Action = "INCIDENT_STATUS_CHANGED"
	ActionAIAnalysisRequested   Action = "AI_ANALYSIS_REQUESTED"
	ActionUserCreated           Action = "USER_CREATED"
	ActionUserDisabled          Action = "USER_DISABLED"
	ActionUserPasswordChanged   Action = "USER_PASSWORD_CHANGED"
	ActionUserPasswordReset     Action = "USER_PASSWORD_RESET"
	ActionMFARequested          Action = "MFA_SETUP_REQUESTED"
	ActionMFAEnabled            Action = "MFA_ENABLED"
	ActionMFADisabled           Action = "MFA_DISABLED"
	ActionMFAReset              Action = "MFA_RESET"
	ActionMFALoginFailure       Action = "MFA_LOGIN_FAILURE"
	ActionMFABackupUsed         Action = "MFA_BACKUP_USED"
	ActionStepUpFailure         Action = "STEP_UP_FAILURE"
	ActionPasskeyRegistered     Action = "PASSKEY_REGISTERED"
	ActionPasskeyDeleted        Action = "PASSKEY_DELETED"
	ActionPasskeyLoginSuccess   Action = "PASSKEY_LOGIN_SUCCESS"
	ActionPasskeyLoginFailure   Action = "PASSKEY_LOGIN_FAILURE"
	ActionBootstrapAdmin        Action = "BOOTSTRAP_ADMIN"
)

// Result is the outcome of an audited operation.
type Result string

const (
	ResultSuccess Result = "success"
	ResultFailure Result = "failure"
	ResultDenied  Result = "denied"
)

// Entry is one audit record.
type Entry struct {
	ID         string    `json:"id"`
	Actor      string    `json:"actor"`
	Action     Action    `json:"action"`
	Resource   string    `json:"resource"`
	ResourceID string    `json:"resource_id"`
	Result     Result    `json:"result"`
	Timestamp  time.Time `json:"timestamp"`
	SourceIP   string    `json:"source_ip,omitempty"`

	// Detail is optional, non-secret context. It must already be redacted.
	Detail string `json:"detail,omitempty"`
}

// Validate checks the audit invariants.
func (e *Entry) Validate() error {
	if e.Actor == "" {
		return fmt.Errorf("audit actor is required")
	}
	if e.Action == "" {
		return fmt.Errorf("audit action is required")
	}
	if e.Resource == "" {
		return fmt.Errorf("audit resource is required")
	}
	switch e.Result {
	case ResultSuccess, ResultFailure, ResultDenied:
	default:
		return fmt.Errorf("audit result %q is not canonical", e.Result)
	}
	if e.Timestamp.IsZero() {
		return fmt.Errorf("audit timestamp is required")
	}
	return nil
}

// ActorKind classifies the acting principal for filtering and display.
type ActorKind string

const (
	ActorUser   ActorKind = "user"
	ActorAgent  ActorKind = "agent"
	ActorSystem ActorKind = "system"
)

// ActorRef builds a canonical actor string.
func ActorRef(kind ActorKind, id string) string {
	return strings.Join([]string{string(kind), id}, ":")
}
