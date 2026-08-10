package privilege

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"

	"macscope/internal/native"
)

const collectorName = "native-read-only"

type Result struct {
	SchemaVersion string               `json:"schema_version"`
	Granted       bool                 `json:"granted"`
	Collector     string               `json:"collector"`
	EffectiveUID  int                  `json:"effective_uid"`
	NativeResults []native.ProbeResult `json:"native_results"`
}

type AuthorizationError struct {
	Executable string
	Cause      error
}

func (err AuthorizationError) Error() string {
	return fmt.Sprintf("sudo authorization failed for privileged collector executable %q: %v", err.Executable, err.Cause)
}

func (err AuthorizationError) Unwrap() error {
	return err.Cause
}

type ProtocolError struct {
	Message string
}

func (err ProtocolError) Error() string {
	return err.Message
}

func Collect(executable string, effectiveUID int, stdin io.Reader, stderr io.Writer) (Result, error) {
	if effectiveUID == 0 {
		return newResult(effectiveUID, native.CollectPrivileged(context.Background())), nil
	}

	command := exec.Command("/usr/bin/sudo", "--", executable, "internal-collect-privileged")
	command.Stdin = stdin
	command.Stderr = stderr

	var output bytes.Buffer
	command.Stdout = &output
	if err := command.Run(); err != nil {
		return Result{}, AuthorizationError{Executable: executable, Cause: err}
	}

	result, err := decodeResult(output.Bytes())
	if err != nil {
		return Result{}, err
	}
	return result, nil
}

func WriteInternalResult(effectiveUID int, output io.Writer) error {
	if effectiveUID != 0 {
		return AuthorizationError{
			Executable: "internal-collect-privileged",
			Cause:      fmt.Errorf("effective UID is %d; this internal command must be launched by sudo", effectiveUID),
		}
	}

	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	result := newResult(effectiveUID, native.CollectPrivileged(context.Background()))
	if err := encoder.Encode(result); err != nil {
		return ProtocolError{Message: fmt.Sprintf("encode privileged collector result: %v", err)}
	}
	return nil
}

func newResult(effectiveUID int, nativeResults []native.ProbeResult) Result {
	return Result{
		SchemaVersion: "2",
		Granted:       effectiveUID == 0,
		Collector:     collectorName,
		EffectiveUID:  effectiveUID,
		NativeResults: append([]native.ProbeResult(nil), nativeResults...),
	}
}

func decodeResult(data []byte) (Result, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var result Result
	if err := decoder.Decode(&result); err != nil {
		return Result{}, ProtocolError{Message: fmt.Sprintf("decode privileged collector result: %v", err)}
	}
	var trailingValue struct{}
	if err := decoder.Decode(&trailingValue); err != io.EOF {
		if err == nil {
			return Result{}, ProtocolError{Message: "decode privileged collector result: unexpected trailing JSON value"}
		}
		return Result{}, ProtocolError{Message: fmt.Sprintf("decode privileged collector trailing data: %v", err)}
	}
	if result.SchemaVersion != "2" {
		return Result{}, ProtocolError{Message: fmt.Sprintf("privileged collector schema version %q is unsupported", result.SchemaVersion)}
	}
	if !result.Granted || result.EffectiveUID != 0 || result.Collector != collectorName {
		return Result{}, ProtocolError{Message: fmt.Sprintf("privileged collector returned invalid authorization evidence: granted=%t effective_uid=%d collector=%q", result.Granted, result.EffectiveUID, result.Collector)}
	}
	if err := native.ValidatePrivilegedResults(result.NativeResults); err != nil {
		return Result{}, ProtocolError{Message: fmt.Sprintf("validate privileged native results: %v", err)}
	}
	return result, nil
}
