package model

import (
	"encoding/json"
	"fmt"
	"io"
)

type DecodeError struct {
	Message string
	Cause   error
}

func (err DecodeError) Error() string {
	return fmt.Sprintf("decode scan document: %s: %v", err.Message, err.Cause)
}

func (err DecodeError) Unwrap() error {
	return err.Cause
}

type EncodeError struct {
	Cause error
}

func (err EncodeError) Error() string {
	return fmt.Sprintf("encode scan document: %v", err.Cause)
}

func (err EncodeError) Unwrap() error {
	return err.Cause
}

func DecodeScanRun(reader io.Reader) (ScanRun, error) {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()

	var run ScanRun
	if err := decoder.Decode(&run); err != nil {
		return ScanRun{}, DecodeError{Message: "invalid JSON or unsupported field", Cause: err}
	}

	var trailingValue struct{}
	if err := decoder.Decode(&trailingValue); err != io.EOF {
		if err == nil {
			return ScanRun{}, DecodeError{Message: "unexpected trailing JSON value", Cause: fmt.Errorf("multiple JSON values are not allowed")}
		}
		return ScanRun{}, DecodeError{Message: "invalid trailing data", Cause: err}
	}
	if err := ValidateScanRun(run); err != nil {
		return ScanRun{}, err
	}
	return run, nil
}

func EncodeScanRun(writer io.Writer, run ScanRun) error {
	if err := ValidateScanRun(run); err != nil {
		return err
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(run); err != nil {
		return EncodeError{Cause: err}
	}
	return nil
}
