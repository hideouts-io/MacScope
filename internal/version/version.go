package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

const Current = "0.1.0-dev"

func BuildSummary() string {
	goVersion := runtime.Version()
	revision := "local"
	modified := ""
	information, available := debug.ReadBuildInfo()
	if available {
		if information.GoVersion != "" {
			goVersion = information.GoVersion
		}
		for _, setting := range information.Settings {
			switch setting.Key {
			case "vcs.revision":
				if strings.TrimSpace(setting.Value) != "" {
					revision = setting.Value
					if len(revision) > 12 {
						revision = revision[:12]
					}
				}
			case "vcs.modified":
				if setting.Value == "true" {
					modified = "+modified"
				}
			}
		}
	}
	return fmt.Sprintf("version %s  |  build %s%s  |  %s/%s  |  %s", Current, revision, modified, runtime.GOOS, runtime.GOARCH, goVersion)
}
