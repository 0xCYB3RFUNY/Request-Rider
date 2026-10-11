package taskcontract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"time"
)

const SchemaVersion = 1

var (
	uuidPattern     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	taskTypePattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]*$`)
)

type Task struct {
	SchemaVersion   int             `json:"schema_version"`
	TaskID          string          `json:"task_id"`
	TaskType        string          `json:"task_type"`
	WorkflowRunID   *int64          `json:"workflow_run_id,omitempty"`
	WorkflowNodeID  string          `json:"workflow_node_id,omitempty"`
	ProjectID       *int64          `json:"project_id,omitempty"`
	RouteGeneration *uint64         `json:"route_generation,omitempty"`
	CreatedAt       string          `json:"created_at"`
	Payload         json.RawMessage `json:"payload"`
	// Sig carries the HMAC-SHA256 over the canonical envelope, keyed by the
	// per-installation broker key. Optional in v1: shape validation ignores it,
	// and the trust boundaries verify it (Go: processTaskDelivery; Django:
	// persist_engine_result). Without a configured key nothing is signed.
	Sig string `json:"sig,omitempty"`
}

type TaskError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

type Result struct {
	SchemaVersion int             `json:"schema_version"`
	TaskID        string          `json:"task_id"`
	EventID       string          `json:"event_id"`
	State         string          `json:"state"`
	OccurredAt    string          `json:"occurred_at"`
	Progress      json.RawMessage `json:"progress,omitempty"`
	Result        json.RawMessage `json:"result,omitempty"`
	Error         *TaskError      `json:"error,omitempty"`
	// Sig carries the HMAC-SHA256 over the canonical envelope, keyed by the
	// per-installation broker key. Optional in v1: shape validation ignores it,
	// and the trust boundaries verify it. Without a configured key nothing is
	// signed.
	Sig string `json:"sig,omitempty"`
}

func (task Task) Validate() error {
	if task.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema_version must be %d", SchemaVersion)
	}
	if err := validateUUID(task.TaskID, "task_id"); err != nil {
		return err
	}
	if !taskTypePattern.MatchString(task.TaskType) {
		return fmt.Errorf("task_type must be a lowercase identifier")
	}
	if task.WorkflowRunID != nil && *task.WorkflowRunID < 1 {
		return fmt.Errorf("workflow_run_id must be a positive integer")
	}
	if task.ProjectID != nil && *task.ProjectID < 1 {
		return fmt.Errorf("project_id must be a positive integer")
	}
	if err := validateTimestamp(task.CreatedAt, "created_at"); err != nil {
		return err
	}
	if err := validateObject(task.Payload, "payload", true); err != nil {
		return err
	}
	return nil
}

func (result Result) Validate() error {
	if result.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema_version must be %d", SchemaVersion)
	}
	if err := validateUUID(result.TaskID, "task_id"); err != nil {
		return err
	}
	if err := validateUUID(result.EventID, "event_id"); err != nil {
		return err
	}
	if err := validateTimestamp(result.OccurredAt, "occurred_at"); err != nil {
		return err
	}
	if result.Progress != nil {
		if err := validateObject(result.Progress, "progress", true); err != nil {
			return err
		}
	}

	switch result.State {
	case "accepted", "progress":
		if result.Result != nil || result.Error != nil {
			return fmt.Errorf("non-terminal results cannot include result or error")
		}
	case "completed":
		if err := validateObject(result.Result, "result", true); err != nil {
			return err
		}
		if result.Error != nil {
			return fmt.Errorf("completed results cannot include error")
		}
	case "failed":
		if result.Error == nil || result.Error.Code == "" || result.Error.Message == "" {
			return fmt.Errorf("failed result requires error code and message")
		}
		if result.Result != nil {
			return fmt.Errorf("failed results cannot include result")
		}
	case "cancelled":
		if result.Result != nil || result.Error != nil {
			return fmt.Errorf("cancelled results cannot include result or error")
		}
	default:
		return fmt.Errorf("state is not supported")
	}
	return nil
}

func validateUUID(value, field string) error {
	if !uuidPattern.MatchString(value) {
		return fmt.Errorf("%s must be a UUID string", field)
	}
	return nil
}

func validateTimestamp(value, field string) error {
	if _, err := time.Parse(time.RFC3339, value); err != nil {
		return fmt.Errorf("%s must be an RFC 3339 timestamp", field)
	}
	return nil
}

func validateObject(value json.RawMessage, field string, required bool) error {
	if len(value) == 0 {
		if required {
			return fmt.Errorf("%s must be an object", field)
		}
		return nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(value, &object); err != nil || object == nil {
		return fmt.Errorf("%s must be an object", field)
	}
	trimmed := bytes.TrimSpace(value)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return fmt.Errorf("%s must be an object", field)
	}
	return nil
}
