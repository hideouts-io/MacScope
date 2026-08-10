package sofa

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientRetriesWithStructuredWarningAndUserAgent(t *testing.T) {
	var requests atomic.Int32
	var observedUserAgent atomic.Value
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		observedUserAgent.Store(request.UserAgent())
		attempt := requests.Add(1)
		if attempt == 1 {
			http.Error(writer, "temporary", http.StatusServiceUnavailable)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"Version":"2.0"}`)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		Endpoint:         server.URL,
		UserAgent:        "MacScope/test",
		Attempts:         2,
		RetryDelays:      []time.Duration{0},
		MaxResponseBytes: 1024,
		HTTPClient:       server.Client(),
	})
	if err != nil {
		t.Fatalf("NewClient returned an error: %v", err)
	}
	var warnings bytes.Buffer
	response, err := client.Fetch(context.Background(), &warnings)
	if err != nil {
		t.Fatalf("Fetch returned an error: %v", err)
	}
	if requests.Load() != 2 {
		t.Fatalf("request count = %d, want 2", requests.Load())
	}
	if observedUserAgent.Load() != "MacScope/test" {
		t.Fatalf("User-Agent = %q, want MacScope/test", observedUserAgent.Load())
	}
	if string(response.Body) != `{"Version":"2.0"}` {
		t.Fatalf("response body = %q", response.Body)
	}
	if !strings.Contains(warnings.String(), `"type":"sofa_fetch_retry"`) || !strings.Contains(warnings.String(), `"attempt":1`) {
		t.Fatalf("warning = %q, want structured retry fields", warnings.String())
	}
}

func TestClientRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(writer, "12345")
	}))
	defer server.Close()
	client, err := NewClient(ClientConfig{
		Endpoint:         server.URL,
		UserAgent:        "MacScope/test",
		Attempts:         1,
		RetryDelays:      make([]time.Duration, 0),
		MaxResponseBytes: 4,
		HTTPClient:       server.Client(),
	})
	if err != nil {
		t.Fatalf("NewClient returned an error: %v", err)
	}
	response, err := client.Fetch(context.Background(), io.Discard)
	if err == nil {
		t.Fatal("Fetch returned nil error for oversized response")
	}
	if string(response.Body) != "1234" {
		t.Fatalf("preserved response body = %q, want first four bytes", response.Body)
	}
}
