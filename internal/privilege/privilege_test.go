package privilege

import (
	"bytes"
	"testing"
)

func TestWriteInternalResultRequiresRoot(t *testing.T) {
	var output bytes.Buffer
	err := WriteInternalResult(501, &output)
	if err == nil {
		t.Fatal("WriteInternalResult returned nil error, want AuthorizationError")
	}
	if output.Len() != 0 {
		t.Fatalf("output length = %d, want 0", output.Len())
	}
}

func TestWriteAndDecodeInternalResult(t *testing.T) {
	var output bytes.Buffer
	if err := WriteInternalResult(0, &output); err != nil {
		t.Fatalf("WriteInternalResult returned an error: %v", err)
	}

	result, err := decodeResult(output.Bytes())
	if err != nil {
		t.Fatalf("decodeResult returned an error: %v", err)
	}
	if !result.Granted || result.EffectiveUID != 0 {
		t.Fatalf("authorization evidence = granted:%t uid:%d, want granted:true uid:0", result.Granted, result.EffectiveUID)
	}
	if len(result.NativeResults) != 2 {
		t.Fatalf("native result count = %d, want 2", len(result.NativeResults))
	}
}

func TestDecodeRejectsUnknownFields(t *testing.T) {
	data := []byte(`{"schema_version":"2","granted":true,"collector":"native-read-only","effective_uid":0,"native_results":[],"unexpected":true}`)
	_, err := decodeResult(data)
	if err == nil {
		t.Fatal("decodeResult returned nil error, want ProtocolError")
	}
}
