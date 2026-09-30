// Package passkey wraps go-webauthn with this service's registration policy and
// the credential handling rules that WebAuthn gets wrong by default.
//
// Ported from ShortLinks (~/Developer/brennanMKE/ShortLinks), which shipped this
// and recorded every wrong turn along the way.
package passkey

import (
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/Kolonnade/Portiko/internal/config"
)

// UserHandleLen is the length of the random WebAuthn user handle.
//
// The handle must be random and opaque. Deriving it from an email breaks every
// passkey when the email changes, and correlates the same person across
// unrelated services if it ever leaks.
const UserHandleLen = 16

// New builds the relying-party instance from configuration.
//
// UserVerification is set at the RP level so the login ceremony inherits it.
// Leaving it unset here makes the browser fall back to the spec default of
// "preferred" while the finish leg still enforces "required" — which locks out
// any client that legitimately returns UV=false. That was ShortLinks #0092.
func New(cfg *config.Config) (*webauthn.WebAuthn, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.WebAuthnRPID,
		RPDisplayName: cfg.ServiceName,
		RPOrigins:     cfg.WebAuthnRPOrigins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationRequired,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("passkey: configuring webauthn: %w", err)
	}
	return wa, nil
}

// RegistrationOptions enforces the enrollment policy:
//
//   - residentKey "required" plus userVerification "required" produce a true
//     discoverable passkey, so a user can sign in without typing anything.
//   - authenticatorAttachment is deliberately OMITTED. Setting "platform"
//     excludes hardware security keys; setting "cross-platform" excludes iCloud
//     Keychain. Leaving it out lets the platform offer both.
//   - ES256 preferred, RS256 accepted.
func RegistrationOptions() []webauthn.RegistrationOption {
	return []webauthn.RegistrationOption{
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			// AuthenticatorAttachment left at its zero value so the field is
			// omitted from the JSON sent to the client.
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		}),
		webauthn.WithCredentialParameters([]protocol.CredentialParameter{
			{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256},
			{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgRS256},
		}),
	}
}

// NextSignCount decides what to store after a successful assertion.
//
// Synced passkeys (iCloud Keychain, Google Password Manager) report a sign count
// of 0 forever, so a naive "counter must advance" rule rejects every login or
// emits a clone warning on every login. The three cases:
//
//	stored 0, asserted 0    → normal synced passkey; keep 0, say nothing
//	asserted <= stored (>0) → possible clone; log it, accept, DO NOT move the
//	                          counter backwards, or a real clone could walk it down
//	asserted > stored       → normal device-bound passkey; store the new value
func NextSignCount(stored, asserted uint32) (next uint32, cloneWarning bool) {
	switch {
	case stored == 0 && asserted == 0:
		return 0, false
	case asserted > stored:
		return asserted, false
	default:
		return stored, true
	}
}
