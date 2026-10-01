package accounts

import (
	"context"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/Kolonnade/Portiko/internal/mailer"
	"github.com/Kolonnade/Portiko/internal/passkey"
	"github.com/Kolonnade/Portiko/internal/store"
)

// StartRegistration accepts an email and sends a one-time code.
//
// It returns nothing about the account either way. An address that is already
// registered gets the same response, and is sent a sign-in code rather than a
// registration code — so the response cannot be used to discover who has an
// account, and a genuine user who forgot they registered still gets in.
func (s *Service) StartRegistration(ctx context.Context, email string) error {
	email = store.NormalizeEmail(email)
	if email == "" {
		return nil // Still silent: an empty address reveals nothing either.
	}

	code, err := newCode()
	if err != nil {
		return err
	}
	token, err := newToken()
	if err != nil {
		return err
	}

	purpose := "registration"
	if _, err := s.db.ByIdentifier(ctx, "email", email); err == nil {
		// The address already has an account, so this is really a recovery:
		// enroll another passkey onto the existing user rather than refusing.
		purpose = "recovery"
	}

	ttl := CodeTTL
	if purpose == "recovery" {
		ttl = RecoveryCodeTTL
	}
	if err := s.db.CreatePending(ctx, store.PendingRegistration{
		Email:     email,
		Token:     token,
		Code:      code,
		Purpose:   purpose,
		ExpiresAt: time.Now().Add(ttl),
	}); err != nil {
		logStep(ctx, "register: creating pending registration", err)
		return nil // Still generic to the caller.
	}

	if err := s.mailer.SendCode(email, code); err != nil {
		logStep(ctx, "register: sending code", err)
	}
	return nil
}

// VerifiedRegistration is the result of exchanging a code for a ceremony.
type VerifiedRegistration struct {
	Token   string
	Email   string
	Purpose string
	Options *protocol.CredentialCreation
}

// VerifyCode exchanges a one-time code for WebAuthn creation options.
func (s *Service) VerifyCode(ctx context.Context, email, code string) (*VerifiedRegistration, error) {
	pending, err := s.db.VerifyPendingCode(ctx, email, code)
	if err != nil {
		logStep(ctx, "register: verifying code", err)
		return nil, ErrAuthFailed
	}

	var user *passkey.User
	switch pending.Purpose {
	case "recovery":
		// Recovery attaches a new credential to the EXISTING account: same user
		// id, same handle. Minting a new handle here would enroll a passkey the
		// account's discoverable login could never match.
		existing, err := s.db.ByIdentifier(ctx, "email", pending.Email)
		if err != nil {
			logStep(ctx, "register: loading account for recovery", err)
			return nil, ErrAuthFailed
		}
		creds, err := s.db.ByUser(ctx, existing.ID)
		if err != nil || len(creds) == 0 {
			logStep(ctx, "register: loading credentials for recovery", err)
			return nil, ErrAuthFailed
		}
		name := s.passkeyName(existing)
		user = &passkey.User{
			ID: existing.ID, Handle: creds[0].UserHandle,
			Name: name, Display: name,
		}
	default:
		handle, err := passkey.NewUserHandle()
		if err != nil {
			return nil, err
		}
		name := s.passkeyName(nil)
		user = &passkey.User{Handle: handle, Name: name, Display: name}
	}

	options, sessionData, err := s.wa.BeginRegistration(user, passkey.RegistrationOptions()...)
	if err != nil {
		logStep(ctx, "register: beginning registration", err)
		return nil, ErrAuthFailed
	}

	blob, err := encodeSession(sessionData)
	if err != nil {
		return nil, err
	}
	if err := s.db.Create(ctx, store.Challenge{
		Challenge:   []byte(sessionData.Challenge),
		Purpose:     "registration",
		PendingTok:  &pending.Token,
		SessionData: blob,
		ExpiresAt:   time.Now().Add(ChallengeTTL),
	}); err != nil {
		logStep(ctx, "register: storing challenge", err)
		return nil, ErrAuthFailed
	}

	return &VerifiedRegistration{
		Token: pending.Token, Email: pending.Email,
		Purpose: pending.Purpose, Options: options,
	}, nil
}

// FinishRegistration verifies the attestation and creates or extends the
// account.
//
// Everything after the challenge is consumed happens in one transaction inside
// the store, so a failure part-way leaves no orphaned user, identifier or
// credential.
func (s *Service) FinishRegistration(ctx context.Context, challenge []byte, response *protocol.ParsedCredentialCreationData, caller Caller) (*store.User, []string, error) {
	// Consume first: a DELETE ... RETURNING makes the challenge single-use, and
	// doing it before the expensive verification means a replayed attestation
	// cannot even be attempted twice.
	stored, err := s.db.ConsumeChallenge(ctx, challenge, "registration")
	if err != nil {
		logStep(ctx, "register: consuming challenge", err)
		return nil, nil, ErrAuthFailed
	}

	sessionData, err := decodeSession(stored.SessionData)
	if err != nil {
		logStep(ctx, "register: decoding session data", err)
		return nil, nil, ErrAuthFailed
	}

	pending, err := s.db.PendingByToken(ctx, derefString(stored.PendingTok))
	if err != nil {
		logStep(ctx, "register: loading pending registration", err)
		return nil, nil, ErrAuthFailed
	}

	// Only the handle is checked against the session here; the name was fixed
	// when the creation options were issued.
	user := &passkey.User{Handle: sessionData.UserID}
	credential, err := s.wa.CreateCredential(user, sessionData, response)
	if err != nil {
		logStep(ctx, "register: creating credential", err)
		return nil, nil, ErrAuthFailed
	}

	rec := passkey.StoredCredential{
		CredentialID: credential.ID,
		PublicKey:    credential.PublicKey,
		UserHandle:   sessionData.UserID,
		AAGUID:       credential.Authenticator.AAGUID,
		SignCount:    credential.Authenticator.SignCount,
		// Both flags are captured HERE, at enrollment, and Backup Eligible is
		// never written again. go-webauthn compares the stored BE against every
		// later assertion; recording it as false for a synced passkey lets the
		// credential enroll and then fail every single login.
		BackupEligible: credential.Flags.BackupEligible,
		BackupState:    credential.Flags.BackupState,
		RPID:           s.cfg.WebAuthnRPID,
	}

	var user2 *store.User
	recovered := pending.Purpose == "recovery"
	if recovered {
		existing, err := s.db.ByIdentifier(ctx, "email", pending.Email)
		if err != nil {
			logStep(ctx, "register: loading account to extend", err)
			return nil, nil, ErrAuthFailed
		}
		rec.UserID = existing.ID
		if err := s.db.Insert(ctx, rec); err != nil {
			logStep(ctx, "register: inserting recovery credential", err)
			return nil, nil, ErrAuthFailed
		}
		user2 = existing
	} else {
		user2, err = s.db.FinishRegistration(ctx, pending.Email, rec, sessionData.UserID)
		if err != nil {
			logStep(ctx, "register: finishing registration", err)
			return nil, nil, ErrAuthFailed
		}
	}

	if err := s.db.DeletePending(ctx, pending.Token); err != nil {
		logStep(ctx, "register: deleting pending registration", err)
	}
	s.recordEnrollment(ctx, user2, rec, recovered, caller)
	return user2, AMR(rec.BackupEligible), nil
}

// recordEnrollment leaves the trail a passkey enrollment owes the account
// holder: an audit row either way, and — when the account already existed — a
// notice to the address that authorized it.
//
// Both halves run after the credential is committed and neither can fail the
// ceremony. The passkey is already enrolled by this point; refusing the sign-in
// because a notice could not be sent would leave the holder with a passkey on
// their account AND no way in, which is strictly worse than a logged failure.
//
// The notice goes only to an account that already existed. A first registration
// is someone sitting in the flow who has just read the code: telling them what
// they are doing teaches them to ignore the message that matters.
func (s *Service) recordEnrollment(ctx context.Context, u *store.User, rec passkey.StoredCredential, recovered bool, caller Caller) {
	name := passkey.AuthenticatorName(rec.AAGUID)
	detail := map[string]any{"recovery": recovered}
	if aaguid := passkey.FormatAAGUID(rec.AAGUID); aaguid != "" {
		detail["aaguid"] = aaguid
	}
	if name != "" {
		detail["authenticator"] = name
	}
	// credential.added is written for a first registration too. An audit trail
	// with a hole where the account began is one an investigation cannot read
	// backwards from.
	s.db.Audit(ctx, store.AuditEvent{
		UserID: &u.ID, Action: store.AuditCredentialAdded,
		IP: caller.IP, UserAgent: caller.UserAgent, Detail: detail,
	})
	if !recovered {
		return
	}
	s.db.Audit(ctx, store.AuditEvent{
		UserID: &u.ID, Action: store.AuditAccountRecovered,
		IP: caller.IP, UserAgent: caller.UserAgent, Detail: detail,
	})

	// The primary address, not the address the code was sent to. They are the
	// same today, because recovery resolves the account from a verified email —
	// but once an account can hold a second address, the notice must reach the
	// one the holder actually reads, not the one the attacker chose.
	to, err := s.db.PrimaryEmail(ctx, u.ID)
	if err != nil {
		logStep(ctx, "register: finding the address to notify of a new passkey", err)
		return
	}
	if err := s.mailer.SendPasskeyAdded(to, mailer.PasskeyNotice{
		When:          time.Now(),
		Authenticator: name,
		ReviewURL:     s.cfg.Issuer + "/",
	}); err != nil {
		logStep(ctx, "register: sending the new-passkey notice", err)
	}
}

// passkeyName is the user name and display name a new passkey is created with.
//
// Never the email address: the provider shows this in every account picker and
// password manager the passkey syncs to. The profile name is used when there
// is one; otherwise the service name, until the holder sets a name and the
// profile page signals the change to the provider.
func (s *Service) passkeyName(u *store.User) string {
	if u != nil && u.DisplayName != "" {
		return u.DisplayName
	}
	return s.cfg.ServiceName
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
