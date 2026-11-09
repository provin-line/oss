package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/o3co/protobuf.interceptors/endpoint"
	pipelineruntime "github.com/provin-line/oss/pipeline/runtime"
	"github.com/provin-line/oss/pipeline/source/ingest/apipush"
)

// The push route bounds a body by its binding's MaxBodySize, the value the
// runtime also gives the binding's source loop.
func TestMountPushRoutes_BoundsABodyByItsBinding(t *testing.T) {
	ready := make(chan struct{})
	close(ready)
	allow := endpoint.NewStaticEndpoint([]endpoint.StaticRule{{Resource: "ingest", Action: "push"}})
	mux := http.NewServeMux()
	b := pipelineruntime.PushBinding{Name: testLoopName, Publisher: fakePublisher{}, Ready: ready, MaxBodySize: 8}
	if err := mountPushRoutes(mux, []pipelineruntime.PushBinding{b}, allow); err != nil {
		t.Fatalf("mountPushRoutes: %v", err)
	}
	post := func(body string) int {
		req := httptest.NewRequest(http.MethodPost, "/ingest/"+testLoopName+"/push", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer tok")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := post(`{"a":12}`); got != http.StatusAccepted {
		t.Errorf("8 bytes at a bound of 8: got %d, want 202", got)
	}
	if got := post(`{"a":123}`); got != http.StatusRequestEntityTooLarge {
		t.Errorf("9 bytes past a bound of 8: got %d, want 413", got)
	}
}

func TestMountPushRoutes_RefusesABindingWithoutABound(t *testing.T) {
	b := pipelineruntime.PushBinding{Name: testLoopName, Publisher: fakePublisher{}, Ready: make(chan struct{})}
	err := mountPushRoutes(http.NewServeMux(), []pipelineruntime.PushBinding{b}, endpoint.NewStaticEndpoint(nil))
	if !errors.Is(err, apipush.ErrInvalidBodyCap) {
		t.Fatalf("got %v, want apipush.ErrInvalidBodyCap", err)
	}
}
