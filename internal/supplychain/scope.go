package supplychain

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

const sfDataless uint32 = 0x40000000

type SyftScope struct {
	ConfigPath       string
	ConfigContent    []byte
	DatalessExcluded int
	UserExcluded     int
}

type datalessPath struct {
	Path        string
	IsDirectory bool
}

type userPathExclusion struct {
	Path        string
	IsDirectory bool
}

func (client Client) PrepareSyftScope(usersRoot string, excludedPaths []string) (SyftScope, error) {
	baseConfig, err := os.ReadFile(client.config.SyftConfigPath)
	if err != nil {
		return SyftScope{}, fmt.Errorf("read fixed Syft configuration %q: %w", client.config.SyftConfigPath, err)
	}
	dataless, err := discoverDatalessICloudPaths(usersRoot)
	if err != nil {
		return SyftScope{}, err
	}
	userExclusions, err := validateUserExclusions(excludedPaths)
	if err != nil {
		return SyftScope{}, err
	}
	projectRoot := filepath.Dir(filepath.Dir(client.config.SyftConfigPath))
	exclusions, err := syftExclusions(projectRoot, dataless, userExclusions)
	if err != nil {
		return SyftScope{}, err
	}
	runtimeConfig, err := buildSyftRuntimeConfig(baseConfig, exclusions)
	if err != nil {
		return SyftScope{}, err
	}
	runtimeDirectory := filepath.Join(filepath.Dir(client.config.SyftExecutablePath), "runtime")
	runtimePath, err := preserveRuntimeConfig(runtimeDirectory, runtimeConfig)
	if err != nil {
		return SyftScope{}, err
	}
	return SyftScope{
		ConfigPath:       runtimePath,
		ConfigContent:    append([]byte(nil), runtimeConfig...),
		DatalessExcluded: len(dataless),
		UserExcluded:     len(userExclusions),
	}, nil
}

func validateUserExclusions(paths []string) ([]userPathExclusion, error) {
	uniquePaths := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if !filepath.IsAbs(path) {
			return nil, fmt.Errorf("validate user-selected Syft exclusion %q: path must be absolute", path)
		}
		cleanPath := filepath.Clean(path)
		if cleanPath == string(filepath.Separator) {
			return nil, fmt.Errorf("validate user-selected Syft exclusion %q: filesystem root cannot be excluded", path)
		}
		uniquePaths[cleanPath] = struct{}{}
	}
	sortedPaths := make([]string, 0, len(uniquePaths))
	for path := range uniquePaths {
		sortedPaths = append(sortedPaths, path)
	}
	sort.Strings(sortedPaths)
	exclusions := make([]userPathExclusion, 0, len(sortedPaths))
	for _, path := range sortedPaths {
		information, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("validate user-selected Syft exclusion %q: inspect path: %w", path, err)
		}
		exclusions = append(exclusions, userPathExclusion{Path: path, IsDirectory: information.IsDir()})
	}
	return exclusions, nil
}

func ValidateExcludedPaths(paths []string) error {
	_, err := validateUserExclusions(paths)
	return err
}

func discoverDatalessICloudPaths(usersRoot string) ([]datalessPath, error) {
	homes, err := os.ReadDir(usersRoot)
	if err != nil {
		return nil, fmt.Errorf("enumerate user homes under %q: %w", usersRoot, err)
	}
	dataless := make([]datalessPath, 0)
	for _, home := range homes {
		if !home.IsDir() {
			continue
		}
		iCloudRoot := filepath.Join(usersRoot, home.Name(), "Library", "Mobile Documents")
		_, err := os.Lstat(iCloudRoot)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("inspect iCloud container root %q: %w", iCloudRoot, err)
		}
		paths, err := walkDatalessPaths(iCloudRoot)
		if err != nil {
			return nil, err
		}
		dataless = append(dataless, paths...)
	}
	sort.Slice(dataless, func(first int, second int) bool {
		return dataless[first].Path < dataless[second].Path
	})
	return dataless, nil
}

func walkDatalessPaths(root string) ([]datalessPath, error) {
	result := make([]datalessPath, 0)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walk iCloud path %q: %w", path, walkErr)
		}
		information, err := entry.Info()
		if err != nil {
			return fmt.Errorf("inspect iCloud path %q without reading content: %w", path, err)
		}
		stat, ok := information.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("inspect iCloud path %q: filesystem metadata is not Darwin syscall.Stat_t", path)
		}
		if stat.Flags&sfDataless == 0 {
			return nil
		}
		result = append(result, datalessPath{Path: path, IsDirectory: entry.IsDir()})
		if entry.IsDir() {
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func syftExclusions(projectRoot string, dataless []datalessPath, userExclusions []userPathExclusion) ([]string, error) {
	exclusions := []string{
		"./dev/**",
		"./Volumes/**",
		"./private/tmp/**",
		"./tmp/**",
		"./System/Volumes/**",
		"./System/Library/AssetsV2/**",
		"./System/Library/Caches/**",
		"./System/Library/Templates/**",
		"./cores/**",
		"./private/var/**",
		"./Library/Caches/**",
		"./Library/SystemMigration/**",
		"./Users/*/Library/Caches/**",
		"./Users/*/Library/CloudStorage/OneDrive*",
		"./Users/*/Library/CloudStorage/OneDrive*/**",
		"./Users/*/OneDrive*",
		"./Users/*/OneDrive*/**",
		"./Users/*/Library/Group Containers/UBF8T346G9.OneDrive*",
		"./Users/*/Library/Group Containers/UBF8T346G9.OneDrive*/**",
		"./Users/*/Library/Containers/com.microsoft.OneDrive*",
		"./Users/*/Library/Containers/com.microsoft.OneDrive*/**",
		"./Users/*/Library/Application Support/OneDrive*",
		"./Users/*/Library/Application Support/OneDrive*/**",
		"./usr/sbin/authserver",
		"./usr/sbin/authserver/**",
		"./usr/sbin/weakpass_edit",
	}
	projectPattern, err := rootRelativeLiteralPattern(projectRoot)
	if err != nil {
		return nil, fmt.Errorf("build Syft project exclusion: %w", err)
	}
	for _, directory := range []string{".tools", "bin", "scan-results"} {
		directoryPattern := projectPattern + "/" + escapeGlobLiteral(directory)
		exclusions = append(exclusions, directoryPattern, directoryPattern+"/**")
	}
	for _, path := range dataless {
		pattern, err := rootRelativeLiteralPattern(path.Path)
		if err != nil {
			return nil, fmt.Errorf("build exclusion for dataless iCloud path %q: %w", path.Path, err)
		}
		exclusions = append(exclusions, pattern)
		if path.IsDirectory {
			exclusions = append(exclusions, pattern+"/**")
		}
	}
	for _, exclusion := range userExclusions {
		pattern, err := rootRelativeLiteralPattern(exclusion.Path)
		if err != nil {
			return nil, fmt.Errorf("build user-selected Syft exclusion for %q: %w", exclusion.Path, err)
		}
		exclusions = append(exclusions, pattern)
		if exclusion.IsDirectory {
			exclusions = append(exclusions, pattern+"/**")
		}
	}
	sort.Strings(exclusions)
	return uniqueStrings(exclusions), nil
}

func rootRelativeLiteralPattern(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("path %q must be absolute", path)
	}
	relative, err := filepath.Rel(string(filepath.Separator), filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("make path %q relative to filesystem root: %w", path, err)
	}
	if relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q must remain below the filesystem root", path)
	}
	components := strings.Split(filepath.ToSlash(relative), "/")
	for index, component := range components {
		components[index] = escapeGlobLiteral(component)
	}
	return "./" + strings.Join(components, "/"), nil
}

func escapeGlobLiteral(value string) string {
	replacer := strings.NewReplacer(
		"\\", "\\\\",
		"*", "\\*",
		"?", "\\?",
		"[", "\\[",
		"]", "\\]",
	)
	return replacer.Replace(value)
}

func buildSyftRuntimeConfig(baseConfig []byte, exclusions []string) ([]byte, error) {
	for _, line := range strings.Split(string(baseConfig), "\n") {
		if strings.HasPrefix(line, "exclude:") {
			return nil, fmt.Errorf("build Syft runtime configuration: fixed configuration already defines top-level exclude")
		}
	}
	result := append([]byte(nil), baseConfig...)
	if len(result) > 0 && result[len(result)-1] != '\n' {
		result = append(result, '\n')
	}
	result = append(result, []byte("exclude:\n")...)
	for _, exclusion := range exclusions {
		encoded, err := json.Marshal(exclusion)
		if err != nil {
			return nil, fmt.Errorf("encode Syft exclusion %q: %w", exclusion, err)
		}
		result = append(result, []byte("  - ")...)
		result = append(result, encoded...)
		result = append(result, '\n')
	}
	return result, nil
}

func preserveRuntimeConfig(directory string, content []byte) (string, error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", fmt.Errorf("create Syft runtime configuration directory %q: %w", directory, err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(content))
	path := filepath.Join(directory, "scope-"+digest[:16]+".yaml")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		existing, readErr := os.ReadFile(path)
		if readErr != nil {
			return "", fmt.Errorf("read existing Syft runtime configuration %q: %w", path, readErr)
		}
		if string(existing) != string(content) {
			return "", fmt.Errorf("validate existing Syft runtime configuration %q: content does not match digest-derived name", path)
		}
		return path, nil
	}
	if err != nil {
		return "", fmt.Errorf("create Syft runtime configuration %q: %w", path, err)
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return "", fmt.Errorf("write Syft runtime configuration %q: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close Syft runtime configuration %q: %w", path, err)
	}
	return path, nil
}
