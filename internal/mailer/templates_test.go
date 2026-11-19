package mailer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeTemplates(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestTemplatesReplaceTheWording(t *testing.T) {
	dir := writeTemplates(t, map[string]string{
		TemplateEmailChanged: "Subject: Your {{.ServiceName}} sign-in addresses changed\n\n" +
			"{{if eq .Change \"added\"}}{{.Address}} was added.{{else}}Something changed.{{end}}\n" +
			"Sign in to check: {{.ReviewURL}}\n",
		"page.html": "<p>not mail</p>",
	})
	ts, err := LoadTemplates(dir)
	if err != nil || ts == nil {
		t.Fatalf("LoadTemplates: %v, %v", ts, err)
	}
	subject, body, ok, err := ts.render(TemplateEmailChanged, EmailChangedData{
		ServiceName: "Example", EmailNotice: EmailNotice{When: time.Now(), Change: EmailAdded,
			Address: "b@example.com", ReviewURL: "https://id.example/emails"},
	})
	if !ok || err != nil {
		t.Fatalf("render: %v %v", ok, err)
	}
	if subject != "Your Example sign-in addresses changed" {
		t.Errorf("subject = %q", subject)
	}
	if body != "b@example.com was added.\r\nSign in to check: https://id.example/emails\r\n" {
		t.Errorf("body = %q", body)
	}
	if strings.Contains(body, "passkey") {
		t.Error("the built-in wording leaked into a custom template")
	}
	// A message with no template of its own keeps the built-in text.
	if _, _, ok, _ := ts.render(TemplateCode, CodeData{}); ok {
		t.Error("a missing template rendered")
	}
}

func TestNoTemplatesIsNil(t *testing.T) {
	ts, err := LoadTemplates(t.TempDir())
	if ts != nil || err != nil {
		t.Errorf("an empty dir: %v, %v", ts, err)
	}
	var none *Templates
	if _, _, ok, _ := none.render(TemplateCode, CodeData{}); ok {
		t.Error("nil templates rendered")
	}
}

// Mistakes stop start-up, not a person's sign-in.
func TestBadTemplatesStopStartup(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"unknown field":  {TemplateCode: "Subject: x\n\n{{.Nope}}"},
		"no subject":     {TemplateCode: "Your code is {{.Code}}"},
		"empty subject":  {TemplateCode: "Subject:\n\n{{.Code}}"},
		"unknown file":   {"mail-welcome.txt": "Subject: hi\n\nhi"},
		"does not parse": {TemplateCode: "Subject: x\n\n{{.Code"},
	} {
		if _, err := LoadTemplates(writeTemplates(t, files)); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

func TestSubjectCannotInjectAHeader(t *testing.T) {
	ts, err := LoadTemplates(writeTemplates(t, map[string]string{
		TemplateEmailChanged: "Subject: changed {{.Address}}\n\nbody\n",
	}))
	if err != nil {
		t.Fatal(err)
	}
	// The newline ends the subject line; what follows becomes the first body
	// line, never a header.
	subject, body, _, err := ts.render(TemplateEmailChanged, EmailChangedData{EmailNotice: EmailNotice{Address: "a@example.com\nBcc: x@evil.example"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(subject, "Bcc") || !strings.HasPrefix(body, "Bcc") {
		t.Errorf("subject %q, body %q", subject, body)
	}
}
