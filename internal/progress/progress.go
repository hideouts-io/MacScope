package progress

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	barWidth   = 24
	clearLine  = "\r\x1b[2K"
	redColor   = "\x1b[91m"
	resetColor = "\x1b[0m"
)

type Event struct {
	Percent int
	Message string
}

type Reporter func(Event) error

type Action func() error

type Tracker struct {
	Report   Reporter
	Suspend  Action
	Resume   Action
	Close    Action
	Messages io.Writer
}

type terminalState struct {
	mutex        sync.Mutex
	writer       io.Writer
	now          func() time.Time
	startedAt    time.Time
	current      Event
	hasEvent     bool
	suspended    bool
	closed       bool
	spinnerIndex int
	writeError   error
}

type progressMessageWriter struct {
	state *terminalState
}

func ShouldDisplay(output *os.File, disabledValue string) (bool, error) {
	if disabledValue == "1" {
		return false, nil
	}
	information, err := output.Stat()
	if err != nil {
		return false, fmt.Errorf("inspect progress output terminal: %w", err)
	}
	return information.Mode()&os.ModeCharDevice != 0, nil
}

func ColorEnabled(noColorValue string, terminal string) bool {
	return noColorValue == "" && terminal != "dumb"
}

func Disabled(messageWriter io.Writer) Tracker {
	return Tracker{
		Report:   discardEvent,
		Suspend:  noAction,
		Resume:   noAction,
		Close:    noAction,
		Messages: messageWriter,
	}
}

func NewPlain(writer io.Writer, now func() time.Time) (Tracker, error) {
	if writer == nil {
		return Tracker{}, fmt.Errorf("configure plain progress: writer must not be nil")
	}
	if now == nil {
		return Tracker{}, fmt.Errorf("configure plain progress: clock must not be nil")
	}
	startedAt := now()
	report := func(event Event) error {
		if err := validateEvent(event); err != nil {
			return err
		}
		line, err := formatLine(event, now().Sub(startedAt), 0, barWidth)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintln(writer, line); err != nil {
			return fmt.Errorf("write plain scan progress: %w", err)
		}
		return nil
	}
	return Tracker{
		Report:   report,
		Suspend:  noAction,
		Resume:   noAction,
		Close:    noAction,
		Messages: writer,
	}, nil
}

func NewTerminal(writer io.Writer, interval time.Duration, now func() time.Time) (Tracker, error) {
	if writer == nil {
		return Tracker{}, fmt.Errorf("configure animated progress: writer must not be nil")
	}
	if interval <= 0 {
		return Tracker{}, fmt.Errorf("configure animated progress: interval must be positive; received %s", interval)
	}
	if now == nil {
		return Tracker{}, fmt.Errorf("configure animated progress: clock must not be nil")
	}
	state := &terminalState{
		writer:    writer,
		now:       now,
		startedAt: now(),
	}
	done := make(chan struct{})
	finished := make(chan struct{})
	ticker := time.NewTicker(interval)
	go animate(state, ticker, done, finished)

	report := func(event Event) error {
		if err := validateEvent(event); err != nil {
			return err
		}
		state.mutex.Lock()
		defer state.mutex.Unlock()
		if state.closed {
			return fmt.Errorf("report scan progress after tracker was closed")
		}
		if state.writeError != nil {
			return state.writeError
		}
		state.current = event
		state.hasEvent = true
		return renderLocked(state)
	}

	suspend := func() error {
		state.mutex.Lock()
		defer state.mutex.Unlock()
		if state.closed {
			return fmt.Errorf("suspend scan progress after tracker was closed")
		}
		if state.writeError != nil {
			return state.writeError
		}
		if state.suspended {
			return nil
		}
		state.suspended = true
		if state.hasEvent {
			if _, err := fmt.Fprint(state.writer, clearLine); err != nil {
				state.writeError = fmt.Errorf("clear scan progress before interactive prompt: %w", err)
				return state.writeError
			}
		}
		return nil
	}

	resume := func() error {
		state.mutex.Lock()
		defer state.mutex.Unlock()
		if state.closed {
			return fmt.Errorf("resume scan progress after tracker was closed")
		}
		if state.writeError != nil {
			return state.writeError
		}
		state.suspended = false
		return renderLocked(state)
	}

	closeTracker := func() error {
		state.mutex.Lock()
		if state.closed {
			err := state.writeError
			state.mutex.Unlock()
			return err
		}
		state.closed = true
		state.mutex.Unlock()
		close(done)
		<-finished

		state.mutex.Lock()
		defer state.mutex.Unlock()
		if state.writeError != nil {
			return state.writeError
		}
		if state.hasEvent && !state.suspended {
			line, err := formatLine(state.current, state.now().Sub(state.startedAt), state.spinnerIndex, barWidth)
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(state.writer, "%s%s%s%s\n", clearLine, redColor, line, resetColor); err != nil {
				return fmt.Errorf("finish scan progress: %w", err)
			}
		}
		return nil
	}

	return Tracker{
		Report:   report,
		Suspend:  suspend,
		Resume:   resume,
		Close:    closeTracker,
		Messages: progressMessageWriter{state: state},
	}, nil
}

func formatLine(event Event, elapsed time.Duration, spinnerIndex int, width int) (string, error) {
	if err := validateEvent(event); err != nil {
		return "", err
	}
	if width < 1 {
		return "", fmt.Errorf("format scan progress: bar width %d must be positive", width)
	}
	if elapsed < 0 {
		return "", fmt.Errorf("format scan progress: elapsed duration %s must not be negative", elapsed)
	}
	percent := event.Percent
	filled := percent * width / 100
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	spinners := []string{"|", "/", "-", "\\"}
	spinner := spinners[positiveModulo(spinnerIndex, len(spinners))]
	return fmt.Sprintf("[%s] %3d%% %s  %s  elapsed %s", bar, percent, spinner, strings.TrimSpace(event.Message), formatElapsed(elapsed)), nil
}

func validateEvent(event Event) error {
	if event.Percent < 0 || event.Percent > 100 {
		return fmt.Errorf("validate scan progress event: percent %d is outside 0 through 100", event.Percent)
	}
	if strings.TrimSpace(event.Message) == "" {
		return fmt.Errorf("validate scan progress event: message must not be empty")
	}
	return nil
}

func animate(state *terminalState, ticker *time.Ticker, done <-chan struct{}, finished chan<- struct{}) {
	defer close(finished)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			state.mutex.Lock()
			if !state.closed && !state.suspended && state.writeError == nil {
				state.writeError = renderLocked(state)
			}
			state.mutex.Unlock()
		case <-done:
			return
		}
	}
}

func renderLocked(state *terminalState) error {
	if !state.hasEvent || state.suspended {
		return nil
	}
	line, err := formatLine(state.current, state.now().Sub(state.startedAt), state.spinnerIndex, barWidth)
	if err != nil {
		return err
	}
	state.spinnerIndex++
	if _, err := fmt.Fprintf(state.writer, "%s%s%s%s", clearLine, redColor, line, resetColor); err != nil {
		return fmt.Errorf("render animated scan progress: %w", err)
	}
	return nil
}

func (writer progressMessageWriter) Write(content []byte) (int, error) {
	state := writer.state
	state.mutex.Lock()
	defer state.mutex.Unlock()
	if state.closed {
		return 0, fmt.Errorf("write scan message after progress tracker was closed")
	}
	if state.writeError != nil {
		return 0, state.writeError
	}
	if state.hasEvent && !state.suspended {
		if _, err := fmt.Fprint(state.writer, clearLine); err != nil {
			state.writeError = fmt.Errorf("clear progress before scan message: %w", err)
			return 0, state.writeError
		}
	}
	written, err := state.writer.Write(content)
	if err != nil {
		state.writeError = fmt.Errorf("write scan message: %w", err)
		return written, state.writeError
	}
	if len(content) > 0 && content[len(content)-1] != '\n' {
		if _, err := fmt.Fprintln(state.writer); err != nil {
			state.writeError = fmt.Errorf("terminate scan message line: %w", err)
			return written, state.writeError
		}
	}
	if !state.suspended {
		if err := renderLocked(state); err != nil {
			state.writeError = err
			return written, err
		}
	}
	return written, nil
}

func formatElapsed(elapsed time.Duration) string {
	totalSeconds := int64(elapsed / time.Second)
	hours := totalSeconds / 3600
	minutes := (totalSeconds % 3600) / 60
	seconds := totalSeconds % 60
	if hours > 0 {
		return fmt.Sprintf("%02d:%02d:%02d", hours, minutes, seconds)
	}
	return fmt.Sprintf("%02d:%02d", minutes, seconds)
}

func positiveModulo(value int, divisor int) int {
	result := value % divisor
	if result < 0 {
		return result + divisor
	}
	return result
}

func discardEvent(event Event) error {
	return validateEvent(event)
}

func noAction() error {
	return nil
}
