package passkey

import (
	"crypto/rand"
	"time"

	"github.com/google/uuid"

	"github.com/go-webauthn/webauthn/webauthn"
)

// NewUserHandle returns a fresh random WebAuthn user handle.
func NewUserHandle() ([]byte, error) {
	b := make([]byte, UserHandleLen)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// User implements webauthn.User for both ceremonies.
//
// During registration the credential list is empty and the handle is freshly
// generated. During login both come from the database. One type serves both so
// the Begin/Finish calls are identical.
type User struct {
	ID          int64
	Handle      []byte
	Name        string
	Display     string
	Credentials []webauthn.Credential
}

func (u *User) WebAuthnID() []byte                         { return u.Handle }
func (u *User) WebAuthnName() string                       { return u.Name }
func (u *User) WebAuthnDisplayName() string                { return u.Display }
func (u *User) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }
func (u *User) WebAuthnIcon() string                       { return "" }

// StoredCredential is a passkey_credentials row.
//
// BackupEligible and BackupState are separate stored columns rather than
// something recomputed, because go-webauthn treats Backup Eligible as immutable:
// the value written at registration must equal the value in every later
// assertion. Losing it lets a synced passkey enroll and never log in, and
// registration still looks like it succeeded because creation compares nothing.
type StoredCredential struct {
	ID             int64
	UserID         int64
	CredentialID   []byte
	PublicKey      []byte
	UserHandle     []byte
	AAGUID         []byte
	SignCount      uint32
	DeviceName     string
	BackupEligible bool
	BackupState    bool
	RPID           string
	// RestrictedUntil is set on a passkey enrolled through recovery: until then,
	// signing in with it does not allow taking away the account's other ways in.
	RestrictedUntil *time.Time
}

// ToWebAuthn rehydrates a stored row into the shape go-webauthn validates
// against. Both flags must be carried across or ValidateLogin rejects the
// assertion with a flag-inconsistency error.
func (s StoredCredential) ToWebAuthn() webauthn.Credential {
	return webauthn.Credential{
		ID:              s.CredentialID,
		PublicKey:       s.PublicKey,
		AttestationType: "none",
		Authenticator: webauthn.Authenticator{
			AAGUID:    s.AAGUID,
			SignCount: s.SignCount,
		},
		Flags: webauthn.CredentialFlags{
			UserPresent:    true,
			UserVerified:   true,
			BackupEligible: s.BackupEligible,
			BackupState:    s.BackupState,
		},
	}
}

// ParseAAGUID decodes the textual AAGUID stored in Postgres.
//
// An all-zero AAGUID is common (iCloud Keychain reports one) and is stored as
// NULL, so an empty string here means "not reported" rather than an error.
func ParseAAGUID(s string) []byte {
	if s == "" {
		return nil
	}
	u, err := uuid.Parse(s)
	if err != nil {
		return nil
	}
	return u[:]
}

// FormatAAGUID renders an AAGUID for storage, mapping absent and all-zero
// values onto the empty string so the column stays NULL.
func FormatAAGUID(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	var u uuid.UUID
	copy(u[:], b)
	if u == uuid.Nil {
		return ""
	}
	return u.String()
}
