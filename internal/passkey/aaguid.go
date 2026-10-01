package passkey

import "github.com/google/uuid"

// AuthenticatorName returns the passkey provider's name for a known AAGUID, or
// the empty string.
//
// The empty string is a real answer, not a failure: most platform authenticators
// report an all-zero AAGUID on purpose, so that a relying party cannot
// fingerprint which device a person uses. A message that must name the
// authenticator would therefore have to guess, and a wrong name in a security
// notice is worse than no name — the holder is being asked "was this you?", and
// an invented answer is what makes them say yes.
//
// The table is deliberately short: the common consumer passkey providers, the
// ones a person would recognise in an email. It comes from the community AAGUID
// list (github.com/passkeydeveloper/passkey-authenticator-aaguids); anything
// absent simply has no name here. Keeping the full list in sync is not worth a
// dependency for one line of one email.
func AuthenticatorName(aaguid []byte) string {
	if len(aaguid) != 16 {
		return ""
	}
	var u uuid.UUID
	copy(u[:], aaguid)
	return aaguidNames[u.String()]
}

var aaguidNames = map[string]string{
	"fbfc3007-154e-4ecc-8c0b-6e020557d7bd": "iCloud Keychain",
	"adce0002-35bc-c60a-648b-0b25f1f05503": "Chrome on Mac",
	"ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4": "Google Password Manager",
	"bada5566-a7aa-401f-bd96-45619a55120d": "1Password",
	"d548826e-79b4-db40-a3d8-11116f7e8349": "Bitwarden",
	"531126d6-e717-415c-9320-3d9aa6981239": "Dashlane",
	"53414d53-554e-4700-0000-000000000000": "Samsung Pass",
	"08987058-cadc-4b81-b6e1-30de50dcbe96": "Windows Hello",
	"9ddd1817-af5a-4672-a2b9-3e3dd95000a9": "Windows Hello",
	"6028b017-b1d4-4c02-b4b3-afcdafc96bb2": "Windows Hello",
	"cb69481e-8ff7-4039-93ec-0a2729a154a8": "YubiKey 5 Series",
	"ee882879-721c-4913-9775-3dfcce97072a": "YubiKey 5 Series",
	"2fc0579f-8113-47ea-b116-bb5a8db9202a": "YubiKey 5 Series",
	"73bb0cd4-e502-49b8-9c6f-b59445bf720b": "YubiKey 5 FIPS Series",
	"c1f9a0bc-1dd2-404a-b27f-8e29047a43fd": "YubiKey 5 FIPS Series",
}
