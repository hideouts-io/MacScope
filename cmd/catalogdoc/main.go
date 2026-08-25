package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"macscope/internal/catalog"
	"macscope/internal/catalogdoc"
)

type options struct {
	markdownPath string
	htmlPath     string
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "catalogdoc: %v\n", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	parsed, err := parseOptions(arguments)
	if err != nil {
		return err
	}
	document, err := catalog.Load()
	if err != nil {
		return err
	}
	markdown, err := catalogdoc.RenderMarkdown(document)
	if err != nil {
		return err
	}
	html, err := catalogdoc.RenderHTML(document)
	if err != nil {
		return err
	}
	if err := writeAtomic(parsed.markdownPath, markdown); err != nil {
		return fmt.Errorf("write Markdown handbook: %w", err)
	}
	if err := writeAtomic(parsed.htmlPath, html); err != nil {
		return fmt.Errorf("write HTML handbook: %w", err)
	}
	return nil
}

func parseOptions(arguments []string) (options, error) {
	set := flag.NewFlagSet("catalogdoc", flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	var parsed options
	set.StringVar(&parsed.markdownPath, "markdown", "", "required Markdown output path")
	set.StringVar(&parsed.htmlPath, "html", "", "required offline HTML output path")
	if err := set.Parse(arguments); err != nil {
		return options{}, err
	}
	if set.NArg() != 0 {
		return options{}, fmt.Errorf("unexpected positional arguments: %s", strings.Join(set.Args(), " "))
	}
	if strings.TrimSpace(parsed.markdownPath) == "" || strings.TrimSpace(parsed.htmlPath) == "" {
		return options{}, errors.New("both --markdown and --html are required")
	}
	return parsed, nil
}

func writeAtomic(path string, content []byte) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve %q: %w", path, err)
	}
	directory := filepath.Dir(absPath)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("create directory %q: %w", directory, err)
	}
	temporary, err := os.CreateTemp(directory, ".catalogdoc-*")
	if err != nil {
		return fmt.Errorf("create temporary file in %q: %w", directory, err)
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set permissions on %q: %w", temporaryPath, err)
	}
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write %q: %w", temporaryPath, err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync %q: %w", temporaryPath, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close %q: %w", temporaryPath, err)
	}
	if err := os.Rename(temporaryPath, absPath); err != nil {
		return fmt.Errorf("replace %q: %w", absPath, err)
	}
	removeTemporary = false
	return nil
}
