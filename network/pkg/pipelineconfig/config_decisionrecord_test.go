package pipelineconfig_test

import (
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/decisionrecord"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
)

func TestLoad_DecisionRecordDefaults(t *testing.T) {
	cfg, err := pipelineconfig.LoadPipelineConfig(loadWith(t, ""))
	if err != nil {
		t.Fatalf("LoadPipelineConfig: %v", err)
	}
	dr := cfg.DecisionRecord
	if dr.Level != decisionrecord.LevelAll || dr.Output != pipelineconfig.DecisionRecordOutputLog || dr.Path != "" || dr.SummaryWindow != time.Minute {
		t.Errorf("decision-record defaults = %+v", dr)
	}
}

func TestLoad_DecisionRecordKeys(t *testing.T) {
	tests := []struct {
		name string
		conf string
		want pipelineconfig.DecisionRecordConfig
	}{
		{"level refusals", `provin.decision-record.level = "refusals"`,
			pipelineconfig.DecisionRecordConfig{Level: decisionrecord.LevelRefusals, Output: pipelineconfig.DecisionRecordOutputLog, SummaryWindow: time.Minute}},
		{"level none", `provin.decision-record.level = "none"`,
			pipelineconfig.DecisionRecordConfig{Level: decisionrecord.LevelNone, Output: pipelineconfig.DecisionRecordOutputLog, SummaryWindow: time.Minute}},
		{"jsonl with path", "provin.decision-record.sink = \"jsonl\"\nprovin.decision-record.path = \"/var/provin/decisions.jsonl\"",
			pipelineconfig.DecisionRecordConfig{Level: decisionrecord.LevelAll, Output: pipelineconfig.DecisionRecordOutputJSONL, Path: "/var/provin/decisions.jsonl", SummaryWindow: time.Minute}},
		{"summary with window", "provin.decision-record.level = \"summary\"\nprovin.decision-record.summary-window = 30s",
			pipelineconfig.DecisionRecordConfig{Level: decisionrecord.LevelSummary, Output: pipelineconfig.DecisionRecordOutputLog, SummaryWindow: 30 * time.Second}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := pipelineconfig.LoadPipelineConfig(loadWith(t, tt.conf))
			if err != nil {
				t.Fatalf("LoadPipelineConfig: %v", err)
			}
			if cfg.DecisionRecord != tt.want {
				t.Errorf("DecisionRecord = %+v, want %+v", cfg.DecisionRecord, tt.want)
			}
		})
	}
}

func TestLoad_DecisionRecordMalformedFailsNamingTheKey(t *testing.T) {
	tests := []struct {
		name    string
		conf    string
		wantKey string
	}{
		{"unknown level", `provin.decision-record.level = "everything"`, "provin.decision-record.level"},
		{"empty level", `provin.decision-record.level = ""`, "provin.decision-record.level"},
		{"level wrong type", `provin.decision-record.level = 1`, "provin.decision-record.level"},
		{"unknown sink", `provin.decision-record.sink = "syslog"`, "provin.decision-record.sink"},
		{"jsonl without path", `provin.decision-record.sink = "jsonl"`, "provin.decision-record.path"},
		{"jsonl with empty path", "provin.decision-record.sink = \"jsonl\"\nprovin.decision-record.path = \"\"", "provin.decision-record.path"},
		{"path with the log sink", "provin.decision-record.path = \"/var/provin/decisions.jsonl\"", "provin.decision-record.path"},
		{"empty path with the log sink", `provin.decision-record.path = ""`, "provin.decision-record.path"},
		{"path wrong type", "provin.decision-record.sink = \"jsonl\"\nprovin.decision-record.path = 1", "provin.decision-record.path"},
		{"zero window", `provin.decision-record.summary-window = 0s`, "provin.decision-record.summary-window"},
		{"negative window", `provin.decision-record.summary-window = -1m`, "provin.decision-record.summary-window"},
		{"malformed window", `provin.decision-record.summary-window = "soon"`, "provin.decision-record.summary-window"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := pipelineconfig.LoadPipelineConfig(loadWith(t, tt.conf))
			if err == nil || !strings.Contains(err.Error(), tt.wantKey) {
				t.Fatalf("got %v, want an error naming %s", err, tt.wantKey)
			}
		})
	}
}
