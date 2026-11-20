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

// Mailer sends the messages the provider owes an account holder: the one-time
// code that starts a ceremony or confirms an address, the notice that a passkey
// was added to an account that already existed, the notice that the
// account's addresses changed, and the notice that its password changed.
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
	SendEmailChanged(to string, n EmailNotice) error
	SendPasswordChanged(to string, n PasswordNotice) error
}

// PasswordChange names what happened to an account's password.
type PasswordChange string

const (
	// PasswordAdded: the account had no password and now has one.
	PasswordAdded PasswordChange = "added"
	// PasswordReplaced: the account's password was replaced with another.
	PasswordReplaced PasswordChange = "changed"
	// PasswordRemoved: the account no longer has a password.
	PasswordRemoved PasswordChange = "removed"
)

// PasswordNotice describes a change to an account's password (PASSWORDS=allow).
// It is sent to the account's primary address, for every change but the one
// that created the account.
type PasswordNotice struct {
	// When the change was made.
	When time.Time
	// Change is what happened.
	Change PasswordChange
	// Recovery is true when the password was set by recovering the account
	// with an emailed code, rather than from the account page while signed in.
	Recovery bool
	// ReviewURL is where the holder can see the account's passkeys and
	// password. As with the other notices, there is no link that undoes it.
	ReviewURL string
}

// EmailChange names what happened to an account's addresses.
type EmailChange string

const (
	// EmailAdded: Address was added to the account as a backup.
	EmailAdded EmailChange = "added"
	// EmailRemoved: Address was taken off the account.
	EmailRemoved EmailChange = "removed"
	// EmailPrimaryChanged: Address became the account's primary; Previous was.
	EmailPrimaryChanged EmailChange = "primary_changed"
)

// EmailNotice describes a change to an account's addresses. It is sent to every
// address on the account, and to the one removed, so a change made by somebody
// else reaches an inbox the holder still reads.
type EmailNotice struct {
	// When the change was made.
	When time.Time
	// Change is what happened.
	Change EmailChange
	// Address is the address added, removed or made primary.
	Address string
	// Previous is the address that was primary, for EmailPrimaryChanged.
	Previous string
	// ReviewURL is where the holder can see the account's addresses. The
	// notice offers no link that undoes the change: that would be a phishing
	// template.
	ReviewURL string
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

func (s *Stdout) SendEmailChanged(to string, n EmailNotice) error {
	slog.Warn("email not configured; printing the address-change notice instead",
		"to", to, "change", string(n.Change), "address", n.Address, "when", n.When, "review", n.ReviewURL)
	return nil
}

func (s *Stdout) SendPasswordChanged(to string, n PasswordNotice) error {
	slog.Warn("email not configured; printing the password notice instead",
		"to", to, "change", string(n.Change), "recovery", n.Recovery, "when", n.When, "review", n.ReviewURL)
	return nil
}

// TestDomains writes messages for a few test domains to the log and passes
// every other message to Next.
//
// Test deployments only. Domains must be lowercase, and config only accepts
// names reserved for testing, so no real mailbox is ever captured. The match
// is exact on the text after the last @: a subdomain of a listed domain is
// not matched, and an address with no @ never is.
type TestDomains struct {
	Domains []string
	Next    Mailer
}

func (t *TestDomains) SendCode(to, code string) error {
	if t.match(to) {
		slog.Warn("test mail domain; not sending, logging instead", "to", to, "code", code)
		return nil
	}
	return t.Next.SendCode(to, code)
}

func (t *TestDomains) SendPasskeyAdded(to string, n PasskeyNotice) error {
	if t.match(to) {
		slog.Warn("test mail domain; not sending, logging instead",
			"to", to, "when", n.When, "authenticator", n.Authenticator, "review", n.ReviewURL)
		return nil
	}
	return t.Next.SendPasskeyAdded(to, n)
}

func (t *TestDomains) SendEmailChanged(to string, n EmailNotice) error {
	if t.match(to) {
		slog.Warn("test mail domain; not sending, logging instead",
			"to", to, "change", string(n.Change), "address", n.Address, "when", n.When, "review", n.ReviewURL)
		return nil
	}
	return t.Next.SendEmailChanged(to, n)
}

func (t *TestDomains) SendPasswordChanged(to string, n PasswordNotice) error {
	if t.match(to) {
		slog.Warn("test mail domain; not sending, logging instead",
			"to", to, "change", string(n.Change), "recovery", n.Recovery, "when", n.When, "review", n.ReviewURL)
		return nil
	}
	return t.Next.SendPasswordChanged(to, n)
}

func (t *TestDomains) match(to string) bool {
	at := strings.LastIndex(to, "@")
	if at < 0 {
		return false
	}
	domain := strings.ToLower(to[at+1:])
	for _, d := range t.Domains {
		if domain == d {
			return true
		}
	}
	return false
}

// SMTP sends through a real server.
type SMTP struct {
	Host, Username, Password, From, ServiceName string
	Port                                        int
	// Templates, when set, replace the built-in wording of the messages they
	// cover. See LoadTemplates.
	Templates *Templates
}

// custom sends name from the deployment's templates. ok is false when there is
// no such template and the built-in text should be used.
func (m *SMTP) custom(to, name string, data any) (ok bool, err error) {
	subject, body, ok, err := m.Templates.render(name, data)
	if !ok || err != nil {
		return ok, err
	}
	return true, m.send(to, subject, body)
}

func (m *SMTP) SendCode(to, code string) error {
	if ok, err := m.custom(to, TemplateCode, CodeData{ServiceName: m.ServiceName, Code: code}); ok {
		return err
	}
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
	if ok, err := m.custom(to, TemplatePasskeyAdded, PasskeyAddedData{ServiceName: m.ServiceName, PasskeyNotice: n}); ok {
		return err
	}
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

// SendEmailChanged tells the holder that the account's addresses changed.
//
// Like the passkey notice, it says what happened and asks for no click: the
// only link is the account itself, where the holder signs in to look.
func (m *SMTP) SendEmailChanged(to string, n EmailNotice) error {
	if ok, err := m.custom(to, TemplateEmailChanged, EmailChangedData{ServiceName: m.ServiceName, EmailNotice: n}); ok {
		return err
	}
	var what, subject string
	switch n.Change {
	case EmailAdded:
		what = fmt.Sprintf("%s was added to your %s account as a backup address. It can\r\n"+
			"now receive sign-in codes and recover the account.", n.Address, m.ServiceName)
		subject = "An email address was added to your " + m.ServiceName + " account"
	case EmailRemoved:
		what = fmt.Sprintf("%s was removed from your %s account. It can no longer\r\n"+
			"receive sign-in codes for it or recover it.", n.Address, m.ServiceName)
		subject = "An email address was removed from your " + m.ServiceName + " account"
	default:
		what = fmt.Sprintf("%s is now the primary email address of your %s account.", n.Address, m.ServiceName)
		if n.Previous != "" {
			what += fmt.Sprintf("\r\nBefore, it was %s.", n.Previous)
		}
		subject = "The primary email address of your " + m.ServiceName + " account changed"
	}
	body := fmt.Sprintf(""+
		"%s\r\n\r\n"+
		"This happened on %s. If you made this change, there is nothing to do.\r\n\r\n"+
		"If you did not, sign in and review the addresses and passkeys on your\r\n"+
		"account:\r\n\r\n"+
		"  %s\r\n",
		what, n.When.UTC().Format("2 January 2006 at 15:04 UTC"), n.ReviewURL)
	return m.send(to, subject, body)
}

// SendPasswordChanged tells the holder that the account's password changed.
//
// Like the other notices it says what happened and asks for no click.
func (m *SMTP) SendPasswordChanged(to string, n PasswordNotice) error {
	if ok, err := m.custom(to, TemplatePasswordChanged, PasswordChangedData{ServiceName: m.ServiceName, PasswordNotice: n}); ok {
		return err
	}
	var what, subject string
	switch n.Change {
	case PasswordRemoved:
		what = fmt.Sprintf("The password was removed from your %s account. It can no longer\r\n"+
			"be used to sign in; your passkeys still can.", m.ServiceName)
		subject = "The password on your " + m.ServiceName + " account was removed"
	case PasswordReplaced:
		what = fmt.Sprintf("The password of your %s account was changed. The old one no longer\r\n"+
			"signs in.", m.ServiceName)
		subject = "The password of your " + m.ServiceName + " account was changed"
	default:
		what = fmt.Sprintf("A password was added to your %s account. It can sign in to your\r\n"+
			"account from now on.", m.ServiceName)
		subject = "A password was added to your " + m.ServiceName + " account"
	}
	how := ""
	if n.Recovery {
		how = "It was done with a sign-in code sent to an address on the account.\r\n"
	}
	body := fmt.Sprintf(""+
		"%s\r\n%s\r\n"+
		"This happened on %s. If you made this change, there is nothing to do.\r\n\r\n"+
		"If you did not, then somebody who can read one of your addresses or who\r\n"+
		"was signed in to your account made it. Sign in and review your passkeys\r\n"+
		"and password:\r\n\r\n"+
		"  %s\r\n",
		what, how, n.When.UTC().Format("2 January 2006 at 15:04 UTC"), n.ReviewURL)
	return m.send(to, subject, body)
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
