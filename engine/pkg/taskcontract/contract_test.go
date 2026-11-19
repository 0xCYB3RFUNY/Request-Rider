package taskcontract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func readContractFixture(t *testing.T, name string, value any) {
	t.Helper()
	path := filepath.Join("..", "..", "..", "contracts", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read shared fixture: %v", err)
	}
	if err := json.Unmarshal(data, value); err != nil {
		t.Fatalf("decode shared fixture: %v", err)
	}
}

func TestSharedTaskFixture(t *testing.T) {
	var task Task
	readContractFixture(t, "engine-task-v1.json", &task)
	if err := task.Validate(); err != nil {
		t.Fatalf("shared task fixture must validate: %v", err)
	}
}

func TestSharedResultFixture(t *testing.T) {
	var result Result
	readContractFixture(t, "engine-result-v1.json", &result)
	if err := result.Validate(); err != nil {
		t.Fatalf("shared result fixture must validate: %v", err)
	}
}

func TestTaskRejectsInvalidPayloadAndCorrelation(t *testing.T) {
	task := Task{
		SchemaVersion: SchemaVersion,
		TaskID:        "6f0e8400-e29b-41d4-a716-446655440000",
		TaskType:      "target.crawl",
		CreatedAt:     "2026-09-27T09:00:00Z",
		Payload:       json.RawMessage(`[]`),
	}
	if err := task.Validate(); err == nil {
		t.Fatal("array payload must be rejected")
	}
	task.Payload = json.RawMessage(`{}`)
	invalidProject := int64(0)
	task.ProjectID = &invalidProject
	if err := task.Validate(); err == nil {
		t.Fatal("non-positive project_id must be rejected")
	}
}

func TestFailedResultRequiresExplicitError(t *testing.T) {
	result := Result{
		SchemaVersion: SchemaVersion,
		TaskID:        "6f0e8400-e29b-41d4-a716-446655440000",
		EventID:       "7f0e8400-e29b-41d4-a716-446655440001",
		State:         "failed",
		OccurredAt:    "2026-09-27T09:00:02Z",
	}
	if err := result.Validate(); err == nil {
		t.Fatal("failed result without error detail must be rejected")
	}
}
