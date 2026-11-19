package mailer

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"text/template"
	"time"
)

// Template names a deployment can supply in its TEMPLATE_DIR. Each is a
// text/template whose output is a "Subject: …" line, a blank line, and the
// body. A message without its file keeps the built-in text.
const (
	TemplateCode         = "mail-code.txt"
	TemplatePasskeyAdded = "mail-passkey-added.txt"
	TemplateEmailChanged = "mail-email-changed.txt"
)

// CodeData is what mail-code.txt is executed with.
type CodeData struct {
	ServiceName string
	Code        string
}

// PasskeyAddedData is what mail-passkey-added.txt is executed with.
type PasskeyAddedData struct {
	ServiceName string
	PasskeyNotice
}

// EmailChangedData is what mail-email-changed.txt is executed with. Change is
// "added", "removed" or "primary_changed".
type EmailChangedData struct {
	ServiceName string
	EmailNotice
}

// Templates are a deployment's own wording for the messages SMTP sends.
type Templates struct{ t *template.Template }

// LoadTemplates reads the mail-*.txt files in dir. It returns nil when there
// are none. Each file is executed once with sample data here, so a template
// that names a field that does not exist, or produces no subject, stops
// start-up instead of failing a person's sign-in.
func LoadTemplates(dir string) (*Templates, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "mail-*.txt"))
	if err != nil || len(matches) == 0 {
		return nil, err
	}
	t, err := template.New("mail").Option("missingkey=error").ParseFiles(matches...)
	if err != nil {
		return nil, fmt.Errorf("mailer: templates: %w", err)
	}
	ts := &Templates{t: t}
	when := time.Date(2026, 1, 2, 3, 4, 0, 0, time.UTC)
	samples := map[string]any{
		TemplateCode:         CodeData{ServiceName: "Example", Code: "123456"},
		TemplatePasskeyAdded: PasskeyAddedData{ServiceName: "Example", PasskeyNotice: PasskeyNotice{When: when, ReviewURL: "https://id.example/passkeys"}},
		TemplateEmailChanged: EmailChangedData{ServiceName: "Example", EmailNotice: EmailNotice{When: when, Change: EmailAdded, Address: "a@example.com", ReviewURL: "https://id.example/emails"}},
	}
	for _, m := range matches {
		name := filepath.Base(m)
		data, known := samples[name]
		if !known {
			return nil, fmt.Errorf("mailer: templates: %s is not a message (want %s, %s or %s)",
				name, TemplateCode, TemplatePasskeyAdded, TemplateEmailChanged)
		}
		if _, _, _, err := ts.render(name, data); err != nil {
			return nil, err
		}
	}
	return ts, nil
}

// render executes name. ok is false when the deployment has no such template.
func (ts *Templates) render(name string, data any) (subject, body string, ok bool, err error) {
	if ts == nil || ts.t.Lookup(name) == nil {
		return "", "", false, nil
	}
	var buf bytes.Buffer
	if err := ts.t.ExecuteTemplate(&buf, name, data); err != nil {
		return "", "", true, fmt.Errorf("mailer: %s: %w", name, err)
	}
	out := strings.ReplaceAll(buf.String(), "\r\n", "\n")
	head, rest, found := strings.Cut(out, "\n")
	subject, hasSubject := strings.CutPrefix(head, "Subject:")
	subject = strings.TrimSpace(subject)
	if !found || !hasSubject || subject == "" {
		return "", "", true, fmt.Errorf("mailer: %s: must start with a \"Subject: …\" line", name)
	}
	// A subject comes from data that includes addresses; a line break in it
	// would start a header of the sender's choosing.
	if strings.ContainsAny(subject, "\r\n") {
		return "", "", true, errors.New("mailer: " + name + ": the subject has a line break")
	}
	rest = strings.TrimPrefix(rest, "\n")
	return subject, strings.ReplaceAll(rest, "\n", "\r\n"), true, nil
}
