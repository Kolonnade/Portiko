package accounts

import (
	"context"
	"errors"
	"time"

	"github.com/Kolonnade/Portiko/internal/mailer"
	"github.com/Kolonnade/Portiko/internal/password"
	"github.com/Kolonnade/Portiko/internal/store"
)

// The opt-in password credential (PASSWORDS=allow). Passkeys stay the
// recommended credential; a password exists for the person whose device cannot
// use one. The emailed code is still only for enrollment and recovery: it can
// lead to a password being set, never to a sign-in by itself.

// AMRPassword is what a password sign-in reports in amr (RFC 8176).
var AMRPassword = []string{"pwd"}

// ErrPasswordsOff is returned by every password operation that adds or uses a
// password while the deployment does not allow them.
var ErrPasswordsOff = errors.New("passwords are not enabled on this deployment")

// WeakPasswordError reports that a new password does not meet the policy.
// Message says why, in words that can be shown as they are.
type WeakPasswordError struct{ Message string }

func (e *WeakPasswordError) Error() string { return "weak password: " + e.Message }

// PasswordsAllowed reports whether the deployment allows passwords.
func (s *Service) PasswordsAllowed() bool { return s.cfg.PasswordsAllowed() }

// checkNew applies the policy to a new password for the account behind email.
func (s *Service) checkNew(pw, email string) (string, error) {
	if err := password.Check(pw, email, s.cfg.ServiceName); err != nil {
		return "", &WeakPasswordError{Message: err.Error()}
	}
	return password.Hash(pw)
}

// FinishPasswordEnrollment ends a verified registration or recovery by setting
// a password instead of creating a passkey. token is VerifiedRegistration.Token.
//
// A password the policy refuses is a *WeakPasswordError and leaves the token
// usable, so the person can choose another. Anything else wrong with the token
// is ErrAuthFailed. A recovered account's password carries the RecoveryHold,
// exactly as a recovered passkey does, and replaces any password it had: that
// is what recovering a forgotten password is. Passkeys are never touched.
func (s *Service) FinishPasswordEnrollment(ctx context.Context, token, pw string, caller Caller) (*store.User, *SignIn, error) {
	if !s.PasswordsAllowed() {
		return nil, nil, ErrPasswordsOff
	}
	pending, err := s.db.PendingByToken(ctx, token)
	if err != nil {
		logStep(ctx, "password enrollment: loading pending registration", err)
		return nil, nil, ErrAuthFailed
	}
	hash, err := s.checkNew(pw, pending.Email)
	if err != nil {
		return nil, nil, err
	}
	var hold *time.Time
	if pending.Purpose == "recovery" {
		h := time.Now().Add(RecoveryHold).UTC()
		hold = &h
	}
	done, err := s.db.FinishPasswordEnrollment(ctx, token, pending.Purpose, hash, hold)
	if err != nil {
		logStep(ctx, "password enrollment: finishing", err)
		return nil, nil, ErrAuthFailed
	}
	u := done.User

	action := store.AuditPasswordSet
	change := mailer.PasswordAdded
	if done.Replaced {
		action, change = store.AuditPasswordChanged, mailer.PasswordReplaced
	}
	detail := map[string]any{"recovery": done.Recovered}
	s.db.Audit(ctx, store.AuditEvent{UserID: &u.ID, Action: action, IP: caller.IP, UserAgent: caller.UserAgent, Detail: detail})
	if done.Recovered {
		s.db.Audit(ctx, store.AuditEvent{UserID: &u.ID, Action: store.AuditAccountRecovered,
			IP: caller.IP, UserAgent: caller.UserAgent, Detail: map[string]any{"credential": "password"}})
		s.notifyPassword(ctx, u.ID, change, true)
	}
	if err := s.db.TouchLogin(ctx, u.ID); err != nil {
		logStep(ctx, "password enrollment: touching account", err)
	}
	return u, &SignIn{AMR: AMRPassword, RestrictedUntil: activeHold(hold)}, nil
}

// PasswordLogin signs in with an address on the account and its password.
//
// Every failure is ErrAuthFailed and takes as long as a wrong password: an
// unknown address, an account with no password, a disabled account and one
// waiting out its backoff all run one decoy verification, so neither the
// answer nor its timing says which it was.
func (s *Service) PasswordLogin(ctx context.Context, email, pw string) (*store.User, *SignIn, error) {
	if !s.PasswordsAllowed() {
		return nil, nil, ErrPasswordsOff
	}
	if len(pw) > 4*password.MaxBytes {
		// Long enough that no password set here can match; not worth hashing.
		logStep(ctx, "password login: refusing an oversized password", nil)
		return nil, nil, ErrAuthFailed
	}
	fail := func(step string, err error) (*store.User, *SignIn, error) {
		password.Decoy(pw)
		logStep(ctx, step, err)
		return nil, nil, ErrAuthFailed
	}
	u, err := s.db.ByIdentifier(ctx, "email", store.NormalizeEmail(email))
	if err != nil {
		return fail("password login: resolving the account", err)
	}
	if !u.Active {
		return fail("password login: account disabled", nil)
	}
	p, err := s.db.BeginPasswordAttempt(ctx, u.ID)
	if err != nil {
		return fail("password login: starting the attempt (no password, or backing off)", err)
	}
	ok, err := password.Verify(pw, p.Hash)
	if err != nil || !ok {
		logStep(ctx, "password login: wrong password", err)
		return nil, nil, ErrAuthFailed
	}
	rehash := ""
	if password.NeedsRehash(p.Hash) {
		if h, err := password.Hash(pw); err == nil {
			rehash = h
		}
	}
	if err := s.db.PasswordSucceeded(ctx, u.ID, rehash); err != nil {
		logStep(ctx, "password login: recording the sign-in", err)
	}
	if err := s.db.TouchLogin(ctx, u.ID); err != nil {
		logStep(ctx, "password login: touching account", err)
	}
	return u, &SignIn{AMR: AMRPassword, RestrictedUntil: activeHold(p.RestrictedUntil)}, nil
}

// SetPassword adds a password to a signed-in account or replaces its own,
// from the account page. hold is the restriction the session making the change
// is under, which the new password inherits: a session that may not take a way
// in away must not be able to mint an unrestricted one either. It reports
// whether a password was replaced.
func (s *Service) SetPassword(ctx context.Context, userID int64, pw string, hold *time.Time, caller Caller) (bool, error) {
	if !s.PasswordsAllowed() {
		return false, ErrPasswordsOff
	}
	primary, err := s.db.PrimaryEmail(ctx, userID)
	if err != nil {
		return false, err
	}
	hash, err := s.checkNew(pw, primary)
	if err != nil {
		return false, err
	}
	replaced, err := s.db.SetPassword(ctx, userID, hash, hold)
	if err != nil {
		return false, err
	}
	action, change := store.AuditPasswordSet, mailer.PasswordAdded
	if replaced {
		action, change = store.AuditPasswordChanged, mailer.PasswordReplaced
	}
	s.db.Audit(ctx, store.AuditEvent{UserID: &userID, Action: action, IP: caller.IP, UserAgent: caller.UserAgent,
		Detail: map[string]any{"recovery": false}})
	s.notifyPassword(ctx, userID, change, false)
	return replaced, nil
}

// RemovePassword takes the password off a signed-in account. It works whether
// or not passwords are allowed, so an account can always drop one. An account
// with no passkey to sign in with instead is store.ErrLastCredential.
func (s *Service) RemovePassword(ctx context.Context, userID int64, caller Caller) error {
	if err := s.db.RemovePassword(ctx, userID); err != nil {
		return err
	}
	s.db.Audit(ctx, store.AuditEvent{UserID: &userID, Action: store.AuditPasswordRemoved, IP: caller.IP, UserAgent: caller.UserAgent})
	s.notifyPassword(ctx, userID, mailer.PasswordRemoved, false)
	return nil
}

// notifyPassword tells the primary address about a password change. Like the
// passkey notice it runs after the change is committed and cannot fail it.
func (s *Service) notifyPassword(ctx context.Context, userID int64, change mailer.PasswordChange, recovery bool) {
	to, err := s.db.PrimaryEmail(ctx, userID)
	if err != nil {
		logStep(ctx, "password: finding the address to notify", err)
		return
	}
	if err := s.mailer.SendPasswordChanged(to, mailer.PasswordNotice{
		When: time.Now(), Change: change, Recovery: recovery, ReviewURL: s.cfg.Issuer + "/passkeys",
	}); err != nil {
		logStep(ctx, "password: sending the notice", err)
	}
}
