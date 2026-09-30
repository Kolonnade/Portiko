package accounts

import (
	"context"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/Kolonnade/Portiko/internal/passkey"
	"github.com/Kolonnade/Portiko/internal/store"
)

// StartLogin issues an assertion challenge.
//
// Two paths produce structurally identical responses:
//
//   - a known email narrows allowCredentials, so the platform prompt is scoped
//   - an unknown or absent email falls back to a discoverable ceremony
//
// Making the two look the same is what stops this endpoint being an
// enumeration oracle. A caller cannot tell whether the address exists.
func (s *Service) StartLogin(ctx context.Context, email string) (*protocol.CredentialAssertion, error) {
	var (
		options     *protocol.CredentialAssertion
		sessionData *webauthn.SessionData
		err         error
		userID      *int64
	)

	if email = store.NormalizeEmail(email); email != "" {
		if u, uerr := s.db.ByIdentifier(ctx, "email", email); uerr == nil {
			if creds, cerr := s.db.ByUser(ctx, u.ID); cerr == nil && len(creds) > 0 {
				wc := make([]webauthn.Credential, 0, len(creds))
				for _, c := range creds {
					wc = append(wc, c.ToWebAuthn())
				}
				id := u.ID
				userID = &id
				options, sessionData, err = s.wa.BeginLogin(&passkey.User{
					ID: u.ID, Handle: creds[0].UserHandle, Name: email, Display: email,
					Credentials: wc,
				})
			}
		}
	}
	if options == nil {
		options, sessionData, err = s.wa.BeginDiscoverableLogin()
	}
	if err != nil {
		logStep(ctx, "login: beginning assertion", err)
		return nil, ErrAuthFailed
	}

	blob, merr := encodeSession(sessionData)
	if merr != nil {
		return nil, merr
	}
	if err := s.db.Create(ctx, store.Challenge{
		Challenge:   []byte(sessionData.Challenge),
		Purpose:     "authentication",
		UserID:      userID,
		SessionData: blob,
		ExpiresAt:   time.Now().Add(ChallengeTTL),
	}); err != nil {
		logStep(ctx, "login: storing challenge", err)
		return nil, ErrAuthFailed
	}
	return options, nil
}

// FinishLogin verifies an assertion and returns the account behind it.
//
// The account is resolved by credential ID, which works for both the scoped and
// the discoverable path — the assertion's rawID identifies the credential
// regardless of how the ceremony was started.
func (s *Service) FinishLogin(ctx context.Context, challenge []byte, response *protocol.ParsedCredentialAssertionData) (*store.User, []string, error) {
	stored, err := s.db.ConsumeChallenge(ctx, challenge, "authentication")
	if err != nil {
		logStep(ctx, "login: consuming challenge", err)
		return nil, nil, ErrAuthFailed
	}

	sd, err := decodeSession(stored.SessionData)
	if err != nil {
		logStep(ctx, "login: decoding session data", err)
		return nil, nil, ErrAuthFailed
	}

	cred, err := s.db.ByCredentialID(ctx, response.RawID)
	if err != nil {
		logStep(ctx, "login: resolving credential", err)
		return nil, nil, ErrAuthFailed
	}
	user, err := s.db.ByID(ctx, cred.UserID)
	if err != nil || !user.Active {
		logStep(ctx, "login: loading account", err)
		return nil, nil, ErrAuthFailed
	}

	creds, err := s.db.ByUser(ctx, user.ID)
	if err != nil {
		logStep(ctx, "login: loading credentials", err)
		return nil, nil, ErrAuthFailed
	}
	wc := make([]webauthn.Credential, 0, len(creds))
	for _, c := range creds {
		wc = append(wc, c.ToWebAuthn())
	}

	// A discoverable ceremony carries no UserID in its session data, so supply
	// the resolved account's handle. go-webauthn checks the assertion's
	// userHandle against it, which is the binding ShortLinks could not make
	// because it never stored the handle.
	if len(sd.UserID) == 0 {
		sd.UserID = cred.UserHandle
	}

	waUser := &passkey.User{
		ID: user.ID, Handle: cred.UserHandle,
		Name: user.DisplayName, Display: user.DisplayName, Credentials: wc,
	}
	validated, err := s.wa.ValidateLogin(waUser, sd, response)
	if err != nil {
		// The likeliest cause here is a Backup Eligible mismatch: the flag
		// recorded at enrollment must equal the one in this assertion.
		logStep(ctx, "login: validating assertion", err)
		return nil, nil, ErrAuthFailed
	}

	next, cloneWarning := passkey.NextSignCount(cred.SignCount, validated.Authenticator.SignCount)
	if cloneWarning {
		logStep(ctx, "login: sign count did not advance (possible clone)", nil)
	}
	if err := s.db.RecordLogin(ctx, cred.CredentialID, next, validated.Flags.BackupState); err != nil {
		logStep(ctx, "login: recording login", err)
	}
	if err := s.db.TouchLogin(ctx, user.ID); err != nil {
		logStep(ctx, "login: touching account", err)
	}
	return user, AMR(cred.BackupEligible), nil
}
