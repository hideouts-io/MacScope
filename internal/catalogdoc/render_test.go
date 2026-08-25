package catalogdoc

import (
	"bytes"
	"testing"

	"macscope/internal/catalog"
)

func TestRenderHandbooksContainEveryCatalogEntryAndInterpretationBoundary(t *testing.T) {
	document, err := catalog.Load()
	if err != nil {
		t.Fatalf("Load returned an error: %v", err)
	}
	markdown, err := RenderMarkdown(document)
	if err != nil {
		t.Fatalf("RenderMarkdown returned an error: %v", err)
	}
	html, err := RenderHTML(document)
	if err != nil {
		t.Fatalf("RenderHTML returned an error: %v", err)
	}
	for _, entry := range document.Rules {
		for format, content := range map[string][]byte{"Markdown": markdown, "HTML": html} {
			if !bytes.Contains(content, []byte(entry.ID)) {
				t.Fatalf("%s does not contain catalog ID %q", format, entry.ID)
			}
		}
	}
	for format, content := range map[string][]byte{"Markdown": markdown, "HTML": html} {
		if !bytes.Contains(content, []byte("not a report of findings detected")) {
			t.Fatalf("%s omits the scan-specific interpretation boundary", format)
		}
	}
}

func TestRenderHTMLAutoescapesCatalogText(t *testing.T) {
	document, err := catalog.Load()
	if err != nil {
		t.Fatalf("Load returned an error: %v", err)
	}
	document.Rules[0].Explanation = "<script>alert('unsafe')</script>"
	html, err := RenderHTML(document)
	if err != nil {
		t.Fatalf("RenderHTML returned an error: %v", err)
	}
	if bytes.Contains(html, []byte("<script>")) {
		t.Fatal("RenderHTML emitted unescaped catalog text")
	}
}
