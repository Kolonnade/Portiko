// Package mailer delivers the provider's messages to an account holder.
//
// SMTP rather than a provider SDK: a self-hosted deployment must be able to
// point at any mail service, and every provider speaks SMTP.
package mailer

import (
	"fmt"
	"log/slog"
	"net/smtp"
	"strings"
	"time"
)

// Mailer sends the two messages the provider owes an account holder: the
// one-time code that starts a ceremony, and the notice that a passkey was added
// to an account that already existed.
//
// The notice is a required method rather than an optional extra. Email is the
// root of trust for recovery — proving you can read the inbox is enough to
// enroll a passkey on an existing account — so a deployment where that happens
// silently gives the holder no way to notice a compromised mailbox. A Mailer
// that sends codes but not notices is not a complete one, and the compiler
// should say so rather than the account holder finding out later.
type Mailer interface {
	SendCode(to, code string) error
	SendPasskeyAdded(to string, n PasskeyNotice) error
}

// PasskeyNotice describes a passkey that has just been added to an account that
// already existed.
type PasskeyNotice struct {
	// When the passkey was enrolled.
	When time.Time
	// Authenticator is the passkey provider's name when the AAGUID identifies
	// one, and empty otherwise. Most platform authenticators deliberately report
	// no AAGUID, so empty is the common case and the message must read sensibly
	// without it.
	Authenticator string
	// ReviewURL is where the holder can see the account's passkeys and act.
	ReviewURL string
}

// Stdout prints messages to the log instead of sending them.
//
// Development only. It is the default when no SMTP host is configured, and it
// logs loudly, because a production deployment that quietly falls back to this
// is one where every sign-in code is in the log file.
type Stdout struct{ ServiceName string }

func (s *Stdout) SendCode(to, code string) error {
	slog.Warn("email not configured; printing the sign-in code instead",
		"to", to, "code", code)
	return nil
}

func (s *Stdout) SendPasskeyAdded(to string, n PasskeyNotice) error {
	slog.Warn("email not configured; printing the new-passkey notice instead",
		"to", to, "when", n.When, "authenticator", n.Authenticator, "review", n.ReviewURL)
	return nil
}

// SMTP sends through a real server.
type SMTP struct {
	Host, Username, Password, From, ServiceName string
	Port                                        int
}

func (m *SMTP) SendCode(to, code string) error {
	return m.send(to, fmt.Sprintf("Your %s sign-in code", m.ServiceName), fmt.Sprintf(""+
		"Your sign-in code is %s\r\n\r\n"+
		"It expires in 10 minutes. If you didn't ask for it, you can ignore this.\r\n",
		code))
}

// SendPasskeyAdded tells the holder that a passkey was added to their account.
//
// The message says what happened, when, and what to do about it — and it asks
// for no click to confirm. A security notice with an action link in it is a
// phishing template; the only link here is the account itself.
func (m *SMTP) SendPasskeyAdded(to string, n PasskeyNotice) error {
	what := "A new passkey"
	if n.Authenticator != "" {
		what = "A new passkey in " + n.Authenticator
	}
	body := fmt.Sprintf(""+
		"%s was added to your %s account on %s.\r\n\r\n"+
		"It can sign in to your account from now on. If you added it, there is\r\n"+
		"nothing to do.\r\n\r\n"+
		"If you did not, then somebody who can read this mailbox added it. Review\r\n"+
		"the passkeys on your account and remove the one you do not recognise:\r\n\r\n"+
		"  %s\r\n",
		what, m.ServiceName, n.When.UTC().Format("2 January 2006 at 15:04 UTC"), n.ReviewURL)
	return m.send(to, "A new passkey was added to your "+m.ServiceName+" account", body)
}

// send writes one message. Headers live here rather than in each caller so a new
// message cannot ship with a malformed header block.
func (m *SMTP) send(to, subject, body string) error {
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s", m.From, to, subject, body)
	addr := fmt.Sprintf("%s:%d", m.Host, m.Port)
	auth := smtp.PlainAuth("", m.Username, m.Password, m.Host)
	if err := smtp.SendMail(addr, auth, m.From, []string{to}, []byte(msg)); err != nil {
		return fmt.Errorf("mailer: sending to %s: %w", redact(to), err)
	}
	return nil
}

// redact keeps an address out of logs while leaving enough to debug with.
func redact(email string) string {
	at := strings.LastIndex(email, "@")
	if at <= 1 {
		return "***"
	}
	return email[:1] + "***" + email[at:]
}
