package pipelineconfig_test

import (
	"strings"
	"testing"

	"github.com/provin-line/oss/network/pkg/pipelineconfig"
)

// An absent sink.payload-delivery defaults to "inline" (the in-org expectation).
func TestLoad_SinkPayloadDelivery_DefaultInline(t *testing.T) {
	pc, err := pipelineconfig.LoadPipelineConfig(loadWith(t, withBearer(loopsConf(validSinkLoop))))
	if err != nil {
		t.Fatalf("LoadPipelineConfig: %v", err)
	}
	if got := pc.Loops[0].Sink.PayloadDelivery; got != "inline" {
		t.Errorf("absent payload-delivery = %q, want inline default", got)
	}
}

// An explicit sink.payload-delivery = "by-reference" loads.
func TestLoad_SinkPayloadDelivery_ByReference(t *testing.T) {
	body := strings.Replace(validSinkLoop,
		`upstream-endpoint = "https://acme.example/pipelines/pipe"`,
		"upstream-endpoint = \"https://acme.example/pipelines/pipe\"\n      payload-delivery = \"by-reference\"", 1)
	pc, err := pipelineconfig.LoadPipelineConfig(loadWith(t, withBearer(loopsConf(body))))
	if err != nil {
		t.Fatalf("LoadPipelineConfig: %v", err)
	}
	if got := pc.Loops[0].Sink.PayloadDelivery; got != "by-reference" {
		t.Errorf("payload-delivery = %q, want by-reference", got)
	}
}

// A malformed sink.payload-delivery is a boot error.
func TestLoad_SinkPayloadDelivery_Malformed(t *testing.T) {
	body := strings.Replace(validSinkLoop,
		`upstream-endpoint = "https://acme.example/pipelines/pipe"`,
		"upstream-endpoint = \"https://acme.example/pipelines/pipe\"\n      payload-delivery = \"streaming\"", 1)
	if _, err := pipelineconfig.LoadPipelineConfig(loadWith(t, withBearer(loopsConf(body)))); err == nil {
		t.Fatal("malformed payload-delivery should be a boot error")
	}
}

// A chained loop honors payload-delivery on its consuming ingress.
func TestLoad_ChainedPayloadDelivery_ByReference(t *testing.T) {
	body := strings.Replace(validChainedLoop,
		`upstream-endpoint = "https://acme.example/pipelines/pipe"`,
		"upstream-endpoint = \"https://acme.example/pipelines/pipe\"\n      payload-delivery = \"by-reference\"", 1)
	pc, err := pipelineconfig.LoadPipelineConfig(loadWith(t, withBearer(loopsConf(body))))
	if err != nil {
		t.Fatalf("LoadPipelineConfig: %v", err)
	}
	if got := pc.Loops[0].Chained.PayloadDelivery; got != "by-reference" {
		t.Errorf("chained payload-delivery = %q, want by-reference", got)
	}
}
