package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"time"
)

// Rotation timing. Both halves of a rotation are a wait, and the waits are not
// arbitrary: they are the two caches a relying party keeps.
const (
	// PublishDelay is how long a new key must be in the published key set before
	// it starts signing. A verifier caches the key set, so a key that signs the
	// moment it is created signs tokens that cached verifiers cannot check. It
	// matches the key-set cache lifetime in internal/verify (15 minutes), which
	// is the longest a well-behaved verifier can be behind.
	PublishDelay = 15 * time.Minute

	// RetireDelay is how long a key must stay published after it stops signing.
	// Dropping it sooner invalidates tokens that are still inside their own
	// lifetime, which is a logout nobody asked for. It matches the longest token
	// lifetime the provider issues (the access token's 15 minutes); the test in
	// provider asserts the two have not drifted apart.
	RetireDelay = 15 * time.Minute
)

// sealMagic marks a stored private key as sealed.
//
// It exists so that plaintext and ciphertext are never confused for one another:
// a PEM key begins "-----BEGIN", and anything that does not begin with this
// prefix is treated as stored in the clear and refused outside development. A
// version digit is included because the day the format changes, the rows already
// written must still be readable.
var sealMagic = []byte("PORTIKOKEY1\x00")

// ErrPlaintextKey is returned when a stored key is not sealed. The message names
// the command to run, because this error is what a deployment sees at startup
// after the migration and before anyone has sealed anything.
var ErrPlaintextKey = errors.New("the private key is stored unencrypted; run \"seal-keys\" to encrypt it, or set DEV_INSECURE=true for local development")

// Sealer encrypts and decrypts signing keys for storage.
//
// The point of the whole exercise is that the database alone is not enough to
// forge a token: the secret lives in the service's environment, so a database
// backup — which a deployment is right to take — is no longer a signing kit.
// It is the same CRYPTO_KEY that encrypts authorization codes, deliberately: a
// second secret to generate, distribute, back up and rotate is a second secret
// to get wrong, and both guard material of exactly the same consequence.
type Sealer struct {
	// Secret is the deployment's 32-byte CRYPTO_KEY.
	Secret [32]byte
	// AllowPlaintext reads a key that is stored in the clear instead of refusing
	// it. Development only — it is wired to DEV_INSECURE.
	AllowPlaintext bool
}

// SealerFor builds the sealer a deployment reads and writes its keys with.
//
// One constructor, so that the link between AllowPlaintext and DEV_INSECURE
// exists in exactly one place: the running service and the operator commands
// must agree about what counts as readable, or an operator seals keys the service
// then refuses, or worse, the other way round.
func SealerFor(cryptoKey [32]byte, devInsecure bool) Sealer {
	return Sealer{Secret: cryptoKey, AllowPlaintext: devInsecure}
}

// Seal encrypts a private key PEM for storage.
//
// The key id is authenticated but not encrypted: it is public, it is in the
// published key set, and binding it into the ciphertext is what stops one row's
// encrypted key from being moved onto another row's id.
func (s Sealer) Seal(kid string, plaintext []byte) ([]byte, error) {
	gcm, err := s.gcm()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("keys: nonce: %w", err)
	}
	out := make([]byte, 0, len(sealMagic)+len(nonce)+len(plaintext)+gcm.Overhead())
	out = append(out, sealMagic...)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plaintext, []byte(kid)), nil
}

// Unseal decrypts a stored private key.
//
// A value that is not sealed is an error, not a fallback: silently accepting
// plaintext is how a deployment ends up believing its keys are encrypted when
// one of them never was. AllowPlaintext is the single explicit exception.
func (s Sealer) Unseal(kid string, stored []byte) ([]byte, error) {
	if !Sealed(stored) {
		if s.AllowPlaintext {
			return stored, nil
		}
		return nil, fmt.Errorf("keys: %s: %w", kid, ErrPlaintextKey)
	}
	gcm, err := s.gcm()
	if err != nil {
		return nil, err
	}
	body := stored[len(sealMagic):]
	if len(body) < gcm.NonceSize() {
		return nil, fmt.Errorf("keys: %s: sealed key is truncated", kid)
	}
	nonce, ciphertext := body[:gcm.NonceSize()], body[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, []byte(kid))
	if err != nil {
		// Naming the likely cause saves an investigation: this is what a wrong or
		// rotated CRYPTO_KEY looks like, and the cipher cannot tell you which.
		return nil, fmt.Errorf("keys: %s: cannot decrypt the private key — is CRYPTO_KEY the one it was sealed with?", kid)
	}
	return plaintext, nil
}

// Sealed reports whether a stored value is encrypted.
func Sealed(stored []byte) bool {
	return len(stored) >= len(sealMagic) && string(stored[:len(sealMagic)]) == string(sealMagic)
}

func (s Sealer) gcm() (cipher.AEAD, error) {
	block, err := aes.NewCipher(s.Secret[:])
	if err != nil {
		return nil, fmt.Errorf("keys: cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("keys: gcm: %w", err)
	}
	return gcm, nil
}
