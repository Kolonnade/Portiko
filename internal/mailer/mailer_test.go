package mailer

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"
)

type recorder struct{ codes, notices, changes, passwords []string }

func (r *recorder) SendPasswordChanged(to string, n PasswordNotice) error {
	r.passwords = append(r.passwords, to)
	return nil
}

func (r *recorder) SendEmailChanged(to string, n EmailNotice) error {
	r.changes = append(r.changes, to)
	return nil
}

func (r *recorder) SendCode(to, code string) error { r.codes = append(r.codes, to); return nil }
func (r *recorder) SendPasskeyAdded(to string, n PasskeyNotice) error {
	r.notices = append(r.notices, to)
	return nil
}

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func TestTestDomainsLogsReservedAddress(t *testing.T) {
	buf := captureLog(t)
	next := &recorder{}
	m := &TestDomains{Domains: []string{"example.test"}, Next: next}
	if err := m.SendCode("a@Example.Test", "123456"); err != nil {
		t.Fatal(err)
	}
	if len(next.codes) != 0 {
		t.Errorf("forwarded: %v", next.codes)
	}
	if !strings.Contains(buf.String(), "code=123456") {
		t.Errorf("log missing code: %q", buf.String())
	}
}

func TestTestDomainsForwardsOthers(t *testing.T) {
	buf := captureLog(t)
	next := &recorder{}
	m := &TestDomains{Domains: []string{"example.test"}, Next: next}
	for _, to := range []string{"a@gmail.com", "a@sub.example.test", "example.test", "a@example.test\r\n"} {
		if err := m.SendCode(to, "123456"); err != nil {
			t.Fatal(err)
		}
	}
	if len(next.codes) != 4 {
		t.Errorf("forwarded %v, want all 4", next.codes)
	}
	if buf.Len() != 0 {
		t.Errorf("unexpected log: %q", buf.String())
	}
}

func TestTestDomainsPasskeyNotice(t *testing.T) {
	buf := captureLog(t)
	next := &recorder{}
	m := &TestDomains{Domains: []string{"example.test"}, Next: next}
	n := PasskeyNotice{When: time.Now(), ReviewURL: "https://id.example.test/passkeys"}
	if err := m.SendPasskeyAdded("a@example.test", n); err != nil {
		t.Fatal(err)
	}
	if err := m.SendPasskeyAdded("a@gmail.com", n); err != nil {
		t.Fatal(err)
	}
	if len(next.notices) != 1 || next.notices[0] != "a@gmail.com" {
		t.Errorf("forwarded %v", next.notices)
	}
	if !strings.Contains(buf.String(), "to=a@example.test") {
		t.Errorf("log missing notice: %q", buf.String())
	}
}

func TestTestDomainsEmailNotice(t *testing.T) {
	buf := captureLog(t)
	next := &recorder{}
	m := &TestDomains{Domains: []string{"example.test"}, Next: next}
	n := EmailNotice{When: time.Now(), Change: EmailAdded, Address: "b@example.test", ReviewURL: "https://id.example.test/emails"}
	if err := m.SendEmailChanged("a@example.test", n); err != nil {
		t.Fatal(err)
	}
	if err := m.SendEmailChanged("a@gmail.com", n); err != nil {
		t.Fatal(err)
	}
	if len(next.changes) != 1 || next.changes[0] != "a@gmail.com" {
		t.Errorf("forwarded %v", next.changes)
	}
	if !strings.Contains(buf.String(), "to=a@example.test") || !strings.Contains(buf.String(), "change=added") {
		t.Errorf("log missing notice: %q", buf.String())
	}
}

func TestTestDomainsPasswordNotice(t *testing.T) {
	buf := captureLog(t)
	next := &recorder{}
	m := &TestDomains{Domains: []string{"example.test"}, Next: next}
	n := PasswordNotice{When: time.Now(), Change: PasswordReplaced, Recovery: true, ReviewURL: "https://id.example.test/passkeys"}
	if err := m.SendPasswordChanged("a@example.test", n); err != nil {
		t.Fatal(err)
	}
	if err := m.SendPasswordChanged("a@gmail.com", n); err != nil {
		t.Fatal(err)
	}
	if len(next.passwords) != 1 || next.passwords[0] != "a@gmail.com" {
		t.Errorf("forwarded %v", next.passwords)
	}
	if !strings.Contains(buf.String(), "to=a@example.test") || !strings.Contains(buf.String(), "change=changed") {
		t.Errorf("log missing notice: %q", buf.String())
	}
}
