package banner

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const (
	resetColor = "\x1b[0m"
	dimColor   = "\x1b[2m"
)

var designs = []string{
	`███╗   ███╗ █████╗  ██████╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
████╗ ████║██╔══██╗██╔════╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
██╔████╔██║███████║██║     ███████╗██║     ██║   ██║██████╔╝█████╗
██║╚██╔╝██║██╔══██║██║     ╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝
██║ ╚═╝ ██║██║  ██║╚██████╗███████║╚██████╗╚██████╔╝██║     ███████╗
╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝`,
	` __  __            ____
|  \/  | __ _  ___/ ___|  ___ ___  _ __   ___
| |\/| |/ _` + "`" + ` |/ __\___ \ / __/ _ \| '_ \ / _ \
| |  | | (_| | (__ ___) | (_| (_) | |_) |  __/
|_|  |_|\__,_|\___|____/ \___\___/| .__/ \___|
                                  |_|`,
	`    __  ___           _____
   /  |/  /___ ______/ ___/_________  ____  ___
  / /|_/ / __ ` + "`" + `/ ___/\__ \/ ___/ __ \/ __ \/ _ \
 / /  / / /_/ / /__ ___/ / /__/ /_/ / /_/ /  __/
/_/  /_/\__,_/\___//____/\___/\____/ .___/\___/
                                   /_/`,
}

var animationColors = []string{
	"\x1b[91m",
	"\x1b[93m",
	"\x1b[92m",
	"\x1b[96m",
	"\x1b[94m",
	"\x1b[95m",
	"\x1b[91m",
}

func ShouldDisplay(output *os.File, disabledValue string) (bool, error) {
	if disabledValue == "1" {
		return false, nil
	}
	information, err := output.Stat()
	if err != nil {
		return false, fmt.Errorf("inspect banner output terminal: %w", err)
	}
	return information.Mode()&os.ModeCharDevice != 0, nil
}

func ColorEnabled(noColorValue string, terminal string) bool {
	return noColorValue == "" && terminal != "dumb"
}

func RenderAnimated(writer io.Writer, sleeper func(time.Duration), random io.Reader, versionSummary string, frameDelay time.Duration) error {
	design, err := selectDesign(random)
	if err != nil {
		return err
	}
	lineCount := strings.Count(design, "\n") + 3
	for index, color := range animationColors {
		if index > 0 {
			if _, err := fmt.Fprintf(writer, "\x1b[%dA\r\x1b[J", lineCount); err != nil {
				return fmt.Errorf("animate MacScope banner frame %d: %w", index+1, err)
			}
		}
		if err := writeColoredFrame(writer, design, versionSummary, color); err != nil {
			return err
		}
		if index < len(animationColors)-1 {
			sleeper(frameDelay)
		}
	}
	if _, err := fmt.Fprintln(writer); err != nil {
		return fmt.Errorf("finish animated MacScope banner: %w", err)
	}
	return nil
}

func RenderPlain(writer io.Writer, random io.Reader, versionSummary string) error {
	design, err := selectDesign(random)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "%s\n%s\nRead-only macOS security posture and vulnerability scanner\n\n", design, versionSummary); err != nil {
		return fmt.Errorf("write plain MacScope banner: %w", err)
	}
	return nil
}

func selectDesign(random io.Reader) (string, error) {
	selection := []byte{0}
	if _, err := io.ReadFull(random, selection); err != nil {
		return "", fmt.Errorf("select random MacScope banner design: %w", err)
	}
	return designs[int(selection[0])%len(designs)], nil
}

func writeColoredFrame(writer io.Writer, design string, versionSummary string, color string) error {
	if _, err := fmt.Fprintf(writer, "%s%s%s\n%s%s%s\n%sRead-only macOS security posture and vulnerability scanner%s\n", color, design, resetColor, color, versionSummary, resetColor, dimColor, resetColor); err != nil {
		return fmt.Errorf("write animated MacScope banner: %w", err)
	}
	return nil
}
