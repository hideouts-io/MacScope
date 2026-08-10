package sofa

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const FeedURL = "https://sofafeed.macadmins.io/v2/macos_data_feed.json"

type ClientConfig struct {
	Endpoint         string
	UserAgent        string
	Attempts         int
	RetryDelays      []time.Duration
	MaxResponseBytes int64
	HTTPClient       *http.Client
}

type Client struct {
	config ClientConfig
}

type FetchResponse struct {
	SourceURL   string
	StartedAt   time.Time
	CompletedAt time.Time
	Body        []byte
}

type FetchError struct {
	Endpoint string
	Attempts int
	Cause    error
}

func (err FetchError) Error() string {
	return fmt.Sprintf("fetch SOFA feed %q after %d attempt(s): %v", err.Endpoint, err.Attempts, err.Cause)
}

func (err FetchError) Unwrap() error {
	return err.Cause
}

type HTTPStatusError struct {
	Endpoint     string
	StatusCode   int
	Status       string
	ResponseBody string
}

func (err HTTPStatusError) Error() string {
	return fmt.Sprintf("SOFA request endpoint=%q returned status_code=%d status=%q response_body=%q", err.Endpoint, err.StatusCode, err.Status, err.ResponseBody)
}

func NewClient(config ClientConfig) (Client, error) {
	parsedEndpoint, err := url.Parse(config.Endpoint)
	if err != nil {
		return Client{}, fmt.Errorf("parse SOFA endpoint %q: %w", config.Endpoint, err)
	}
	if parsedEndpoint.Scheme != "https" || parsedEndpoint.Host == "" {
		return Client{}, fmt.Errorf("SOFA endpoint %q must be an absolute HTTPS URL", config.Endpoint)
	}
	if strings.TrimSpace(config.UserAgent) == "" {
		return Client{}, fmt.Errorf("SOFA user agent must not be empty")
	}
	if config.Attempts < 1 {
		return Client{}, fmt.Errorf("SOFA attempts must be at least 1; received %d", config.Attempts)
	}
	if len(config.RetryDelays) != config.Attempts-1 {
		return Client{}, fmt.Errorf("SOFA retry delay count must be attempts minus one; received %d delays for %d attempts", len(config.RetryDelays), config.Attempts)
	}
	for index, delay := range config.RetryDelays {
		if delay < 0 {
			return Client{}, fmt.Errorf("SOFA retry delay %d must not be negative; received %s", index, delay)
		}
	}
	if config.MaxResponseBytes < 1 {
		return Client{}, fmt.Errorf("SOFA maximum response size must be positive; received %d", config.MaxResponseBytes)
	}
	if config.HTTPClient == nil {
		return Client{}, fmt.Errorf("SOFA HTTP client must not be nil")
	}
	return Client{config: config}, nil
}

func (client Client) Fetch(parentContext context.Context, warningWriter io.Writer) (FetchResponse, error) {
	startedAt := time.Now().UTC()
	lastResponse := FetchResponse{SourceURL: client.config.Endpoint, StartedAt: startedAt, Body: make([]byte, 0)}
	var lastError error
	for attempt := 1; attempt <= client.config.Attempts; attempt++ {
		body, err := client.fetchAttempt(parentContext)
		lastResponse = FetchResponse{
			SourceURL:   client.config.Endpoint,
			StartedAt:   startedAt,
			CompletedAt: time.Now().UTC(),
			Body:        body,
		}
		if err == nil {
			return lastResponse, nil
		}
		lastError = err
		if attempt == client.config.Attempts {
			break
		}
		delay := client.config.RetryDelays[attempt-1]
		if err := writeRetryWarning(warningWriter, client.config.Endpoint, attempt, client.config.Attempts, delay, lastError); err != nil {
			return lastResponse, FetchError{Endpoint: client.config.Endpoint, Attempts: attempt, Cause: fmt.Errorf("request error: %v; retry warning error: %w", lastError, err)}
		}
		if err := waitForRetry(parentContext, delay); err != nil {
			return lastResponse, FetchError{Endpoint: client.config.Endpoint, Attempts: attempt, Cause: err}
		}
	}
	return lastResponse, FetchError{Endpoint: client.config.Endpoint, Attempts: client.config.Attempts, Cause: lastError}
}

func (client Client) fetchAttempt(parentContext context.Context) ([]byte, error) {
	request, err := http.NewRequestWithContext(parentContext, http.MethodGet, client.config.Endpoint, nil)
	if err != nil {
		return make([]byte, 0), fmt.Errorf("create SOFA GET request endpoint=%q: %w", client.config.Endpoint, err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", client.config.UserAgent)
	response, err := client.config.HTTPClient.Do(request)
	if err != nil {
		return make([]byte, 0), fmt.Errorf("execute SOFA GET request endpoint=%q: %w", client.config.Endpoint, err)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, client.config.MaxResponseBytes+1))
	closeErr := response.Body.Close()
	if readErr != nil {
		return body, fmt.Errorf("read SOFA response endpoint=%q status_code=%d: %w", client.config.Endpoint, response.StatusCode, readErr)
	}
	if closeErr != nil {
		return body, fmt.Errorf("close SOFA response endpoint=%q status_code=%d: %w", client.config.Endpoint, response.StatusCode, closeErr)
	}
	if int64(len(body)) > client.config.MaxResponseBytes {
		return body[:client.config.MaxResponseBytes], fmt.Errorf("SOFA response endpoint=%q exceeded maximum size of %d bytes", client.config.Endpoint, client.config.MaxResponseBytes)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return body, HTTPStatusError{
			Endpoint:     client.config.Endpoint,
			StatusCode:   response.StatusCode,
			Status:       response.Status,
			ResponseBody: truncateResponseBody(body, 4096),
		}
	}
	return body, nil
}

func writeRetryWarning(writer io.Writer, endpoint string, attempt int, attempts int, delay time.Duration, requestError error) error {
	payload := struct {
		Level        string `json:"level"`
		Type         string `json:"type"`
		Endpoint     string `json:"endpoint"`
		Attempt      int    `json:"attempt"`
		Attempts     int    `json:"attempts"`
		RetryDelayMS int64  `json:"retry_delay_ms"`
		Error        string `json:"error"`
	}{
		Level:        "warning",
		Type:         "sofa_fetch_retry",
		Endpoint:     endpoint,
		Attempt:      attempt,
		Attempts:     attempts,
		RetryDelayMS: delay.Milliseconds(),
		Error:        requestError.Error(),
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode structured SOFA retry warning: %w", err)
	}
	if _, err := fmt.Fprintln(writer, string(encoded)); err != nil {
		return fmt.Errorf("write structured SOFA retry warning: %w", err)
	}
	return nil
}

func waitForRetry(parentContext context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-parentContext.Done():
		return fmt.Errorf("SOFA retry canceled: %w", parentContext.Err())
	case <-timer.C:
		return nil
	}
}

func truncateResponseBody(body []byte, maximumBytes int) string {
	if len(body) <= maximumBytes {
		return string(body)
	}
	return string(body[:maximumBytes])
}
