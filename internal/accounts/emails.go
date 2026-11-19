package accounts

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/Kolonnade/Portiko/internal/mailer"
	"github.com/Kolonnade/Portiko/internal/store"
)

// EmailCodeTTL is how long the code confirming a new address stays good.
const EmailCodeTTL = 10 * time.Minute

// Errors of the address changes that a caller may show. Every other failure is
// ErrAuthFailed.
var (
	// ErrInvalidEmail: the address is not one a code could be sent to.
	ErrInvalidEmail = errors.New("not an email address")
	// ErrEmailLimit: the account holds as many addresses as it may.
	ErrEmailLimit = errors.New("the account holds the most addresses it may")
	// ErrPrimaryEmail: the primary cannot be removed.
	ErrPrimaryEmail = errors.New("the primary address cannot be removed")
	// ErrEmailNotFound: not one of the account's addresses.
	ErrEmailNotFound = errors.New("no such address on the account")
)

// validEmail reports whether a normalized address is a bare addr-spec with a
// domain: what a code can be sent to, and nothing with a display name, angle
// brackets or a second address hidden in it.
func validEmail(email string) bool {
	if email == "" || len(email) > 254 || strings.ContainsAny(email, " <>,;") {
		return false
	}
	a, err := mail.ParseAddress(email)
	if err != nil || a.Address != email || a.Name != "" {
		return false
	}
	at := strings.LastIndex(email, "@")
	return at > 0 && strings.Contains(email[at+1:], ".")
}

// StartAddEmail sends a code to an address being added to the account.
//
// An address that is already on an account, this one or another, gets the same
// answer as one that is not, and is sent nothing: whether an address has an
// account must not be learnable from here any more than from sign-in. The code
// then never arrives, and verifying fails like a wrong code. The limit is the
// account's own business and is answered plainly.
func (s *Service) StartAddEmail(ctx context.Context, userID int64, email string) error {
	email = store.NormalizeEmail(email)
	if !validEmail(email) {
		return ErrInvalidEmail
	}
	held, err := s.db.Emails(ctx, userID)
	if err != nil {
		return err
	}
	if len(held) >= s.cfg.EmailLimit() {
		return ErrEmailLimit
	}
	taken, err := s.db.EmailInUse(ctx, email)
	if err != nil {
		return err
	}
	if taken {
		logStep(ctx, "emails: not sending a code to an address already on an account", nil)
		return nil
	}
	code, err := newCode()
	if err != nil {
		return err
	}
	if err := s.db.CreatePendingEmail(ctx, userID, email, code, time.Now().Add(EmailCodeTTL)); err != nil {
		return err
	}
	if err := s.mailer.SendCode(email, code); err != nil {
		logStep(ctx, "emails: sending code", err)
	}
	return nil
}

// VerifyAddEmail checks the code and adds the address as a backup. Every failure
// that could reveal another account — a wrong, expired or missing code, or the
// address taken in the meantime — is ErrAuthFailed wrapping the cause, for the
// provider's events; ErrEmailLimit is the account's own and is returned as is.
func (s *Service) VerifyAddEmail(ctx context.Context, userID int64, email, code string, caller Caller) (*store.Email, error) {
	email = store.NormalizeEmail(email)
	added, err := s.db.AddVerifiedEmail(ctx, userID, email, code, s.cfg.EmailLimit())
	switch {
	case errors.Is(err, store.ErrEmailLimit):
		return nil, ErrEmailLimit
	case err != nil:
		logStep(ctx, "emails: verifying an added address", err)
		return nil, fmt.Errorf("%w: %w", ErrAuthFailed, err)
	}
	s.db.Audit(ctx, store.AuditEvent{
		UserID: &userID, Action: store.AuditEmailAdded, IP: caller.IP, UserAgent: caller.UserAgent,
		Detail: map[string]any{"email": Redact(added.Address)},
	})
	s.notifyEmails(ctx, userID, mailer.EmailNotice{Change: mailer.EmailAdded, Address: added.Address})
	return added, nil
}

// MakePrimary makes one of the account's addresses its primary. Making the
// primary primary again changes nothing and sends nothing.
func (s *Service) MakePrimary(ctx context.Context, userID, id int64, caller Caller) error {
	previous, current, err := s.db.SetPrimaryEmail(ctx, userID, id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrEmailNotFound
	case err != nil:
		return err
	}
	if previous == current {
		return nil
	}
	s.db.Audit(ctx, store.AuditEvent{
		UserID: &userID, Action: store.AuditEmailPrimaryChanged, IP: caller.IP, UserAgent: caller.UserAgent,
		Detail: map[string]any{"from": Redact(previous), "to": Redact(current)},
	})
	s.notifyEmails(ctx, userID, mailer.EmailNotice{
		Change: mailer.EmailPrimaryChanged, Address: current, Previous: previous,
	})
	return nil
}

// RemoveEmail takes a backup address off the account. The removed address is
// told too: it is the one an attacker would remove to keep the holder from
// hearing about anything else.
func (s *Service) RemoveEmail(ctx context.Context, userID, id int64, caller Caller) error {
	removed, err := s.db.RemoveEmail(ctx, userID, id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrEmailNotFound
	case errors.Is(err, store.ErrPrimaryEmail):
		return ErrPrimaryEmail
	case err != nil:
		return err
	}
	s.db.Audit(ctx, store.AuditEvent{
		UserID: &userID, Action: store.AuditEmailRemoved, IP: caller.IP, UserAgent: caller.UserAgent,
		Detail: map[string]any{"email": Redact(removed)},
	})
	s.notifyEmails(ctx, userID, mailer.EmailNotice{Change: mailer.EmailRemoved, Address: removed}, removed)
	return nil
}

// notifyEmails sends a notice to every address on the account and to extra.
// Like the passkey notice, it runs after the change is committed and cannot
// undo it: a failure is logged.
func (s *Service) notifyEmails(ctx context.Context, userID int64, n mailer.EmailNotice, extra ...string) {
	n.When = time.Now()
	n.ReviewURL = s.cfg.Issuer + "/emails"
	held, err := s.db.Emails(ctx, userID)
	if err != nil {
		logStep(ctx, "emails: finding the addresses to notify", err)
	}
	to := make([]string, 0, len(held)+len(extra))
	for _, e := range held {
		to = append(to, e.Address)
	}
	to = append(to, extra...)
	for _, addr := range to {
		if err := s.mailer.SendEmailChanged(addr, n); err != nil {
			logStep(ctx, "emails: sending the address-change notice", err)
		}
	}
}

// Redact keeps an address out of logs and audit rows while leaving enough to
// tell two apart: the first character of the mailbox and the whole domain.
func Redact(email string) string {
	at := strings.LastIndex(email, "@")
	if at < 1 {
		return "***"
	}
	return email[:1] + "***" + email[at:]
}
