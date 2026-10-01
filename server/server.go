// Package server is the Portiko command: it runs the provider and the operator
// commands that register the sites allowed to sign people in.
//
// A deployment's own binary is usually a few lines that call Main, supplying
// whatever extension points the deployment fills.
package server

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Kolonnade/Portiko/internal/keys"
	"github.com/Kolonnade/Portiko/internal/store"
	"github.com/Kolonnade/Portiko/provider"
)

// Main runs the command named by args[0] and returns the process exit code.
func Main(name string, args []string, opts provider.Options) int {
	cmd := ""
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(opts)
	case "register-client":
		err = registerClient(name, args)
	case "set-logout-uri":
		err = setClientURI(cmd, args, (*store.DB).SetBackchannelLogoutURI)
	case "set-events-uri":
		err = setClientURI(cmd, args, (*store.DB).SetEventsURI)
	case "set-scopes":
		err = setScopes(args)
	case "keys":
		err = listKeys(os.Stdout)
	case "rotate-key":
		err = rotateKey()
	case "activate-key":
		err = activateKey(args)
	case "retire-key":
		err = retireKey(args)
	case "seal-keys":
		err = sealKeys()
	case "unseal-keys":
		err = unsealKeys()
	default:
		usage(os.Stdout, name)
		if cmd != "" && cmd != "help" {
			return 2
		}
		return 0
	}
	if err != nil {
		slog.Error(name, "command", cmd, "err", err)
		return 1
	}
	return 0
}

func usage(w io.Writer, name string) {
	fmt.Fprintf(w, `%[1]s — a Portiko identity provider

usage:
  %[1]s serve
  %[1]s register-client [-public] [-first-party] [-scopes openid,profile,offline_access] <id> <audience> <redirect-uri> [secret]
  %[1]s set-logout-uri <client-id> <back-channel-logout-uri>
  %[1]s set-events-uri <client-id> <events-uri>
  %[1]s set-scopes <client-id> <scope,scope,...>

  %[1]s keys
  %[1]s rotate-key
  %[1]s activate-key [-force] <kid>
  %[1]s retire-key [-force] <kid>
  %[1]s seal-keys
  %[1]s unseal-keys

Rotating the signing key is three steps with a wait between each, because a
verifier caches the key set and tokens outlive the key that signed them. See
docs/key-rotation.md.

Configuration comes from the environment; see the Portiko README.
`, name)
}

func serve(opts provider.Options) error {
	cfg, err := provider.LoadConfig()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	p, err := provider.New(ctx, cfg, opts)
	if err != nil {
		return err
	}
	defer p.Close()
	go p.Sweep(ctx)

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		Handler:           p.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	errCh := make(chan error, 1)
	go func() {
		slog.Info("listening", "addr", srv.Addr, "issuer", cfg.Issuer, "rp_id", cfg.WebAuthnRPID,
			"protocol", provider.Preferred.String())
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	// Drain rather than cut: a ceremony killed mid-transaction is exactly the
	// half-state this service must not create.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	slog.Info("shutting down")
	return srv.Shutdown(shutdownCtx)
}

func openStore() (*provider.Config, *store.DB, error) {
	cfg, err := provider.LoadConfig()
	if err != nil {
		return nil, nil, err
	}
	db, err := store.Open(context.Background(), cfg.DatabaseURL)
	return cfg, db, err
}

// registerClient adds or updates a site. Manual registration is deliberate: open
// registration needs domain verification and a consent screen first.
func registerClient(name string, args []string) error {
	fs := flag.NewFlagSet("register-client", flag.ContinueOnError)
	public := fs.Bool("public", false, "a public client (a native app): no secret, PKCE only")
	firstParty := fs.Bool("first-party", false, "operated by this deployment; skips consent")
	scopes := fs.String("scopes", "openid,profile,offline_access", "scopes the client may be granted")
	// The proof of concept's positional form ends with "first_party"; accept it.
	positional := []string{}
	for _, a := range args {
		if a == "first_party" {
			*firstParty = true
			continue
		}
		positional = append(positional, a)
	}
	if err := fs.Parse(positional); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) < 3 || (!*public && len(rest) < 4) {
		usage(os.Stderr, name)
		return errors.New("register-client needs <id> <audience> <redirect-uri> and, unless -public, <secret>")
	}
	secret := ""
	if !*public {
		secret = rest[3]
	}
	tier := "third_party"
	if *firstParty {
		tier = "first_party"
	}
	appType := "web"
	if *public {
		appType = "native"
	}
	_, db, err := openStore()
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.UpsertClient(context.Background(), store.Client{
		ClientID: rest[0], Audience: rest[1], DisplayName: rest[0],
		RedirectURIs: []string{rest[2]}, TrustTier: tier, ApplicationType: appType,
		AllowedScopes: splitList(*scopes),
	}, secret); err != nil {
		return err
	}
	slog.Info("client registered", "client_id", rest[0], "audience", rest[1], "trust_tier", tier, "type", appType)
	return nil
}

// setClientURI records one of a client's server-to-server URIs. An empty uri
// turns it off.
func setClientURI(cmd string, args []string, set func(*store.DB, context.Context, string, string) error) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: %s <client-id> <uri>", cmd)
	}
	cfg, db, err := openStore()
	if err != nil {
		return err
	}
	defer db.Close()
	if args[1] != "" {
		u, err := url.Parse(args[1])
		if err != nil || u.Host == "" || (u.Scheme != "https" && !(cfg.DevInsecure && u.Scheme == "http")) {
			return fmt.Errorf("%s: %q must be an absolute https URL", cmd, args[1])
		}
	}
	if err := set(db, context.Background(), args[0], args[1]); err != nil {
		return fmt.Errorf("%s %s: %w", cmd, args[0], err)
	}
	slog.Info("client URI set", "command", cmd, "client_id", args[0], "uri", args[1])
	return nil
}

func setScopes(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: set-scopes <client-id> <scope,scope,...>")
	}
	_, db, err := openStore()
	if err != nil {
		return err
	}
	defer db.Close()
	scopes := splitList(args[1])
	if err := db.SetAllowedScopes(context.Background(), args[0], scopes); err != nil {
		return fmt.Errorf("set-scopes %s: %w", args[0], err)
	}
	slog.Info("client scopes set", "client_id", args[0], "scopes", scopes)
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ------------------------------------------------------------------- keys
//
// Rotation is three operator steps rather than one command that sleeps, because
// each phase has to wait for a cache somewhere else to turn over — up to fifteen
// minutes — and a command holding a terminal open for that long is a command that
// gets killed half way. Each step prints what to run next.
//
// The running service loads its key ring at startup, so it must be restarted
// after `activate-key` and after `retire-key` before the change is served.

func listKeys(w io.Writer) error {
	_, db, err := openStore()
	if err != nil {
		return err
	}
	defer db.Close()
	ring, err := db.Keys(context.Background())
	if err != nil {
		return err
	}
	if len(ring) == 0 {
		fmt.Fprintln(w, "no signing keys yet; one is created at first start")
		return nil
	}
	fmt.Fprintf(w, "%-24s %-9s %-9s %-20s %s\n", "KID", "STATE", "AT REST", "CREATED", "ACTIVATED")
	for _, k := range ring {
		atRest := "sealed"
		if !k.Sealed {
			atRest = "PLAINTEXT"
		}
		fmt.Fprintf(w, "%-24s %-9s %-9s %-20s %s\n",
			k.KID, k.State, atRest, k.CreatedAt.UTC().Format(time.RFC3339), stamp(k.ActivatedAt))
	}
	return nil
}

func stamp(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

func rotateKey() error {
	cfg, db, err := openStore()
	if err != nil {
		return err
	}
	defer db.Close()
	k, err := db.BeginRotation(context.Background(), sealer(cfg))
	if err != nil {
		return fmt.Errorf("rotate-key: %w", err)
	}
	slog.Info("new signing key published, not yet signing", "kid", k.KID, "state", k.State)
	fmt.Printf(`
A new key %s is published and is NOT signing yet.

  1. Restart the service so it serves the new key in its key set.
  2. Wait %s for verifiers' cached key sets to pick it up.
  3. activate-key %s   — then restart again; the new key starts signing.
  4. Wait %s for tokens signed by the old key to expire.
  5. retire-key <old kid>   — then restart again.

Run "keys" at any point to see where the rotation stands.
`, k.KID, keys.PublishDelay, k.KID, keys.RetireDelay)
	return nil
}

func activateKey(args []string) error {
	kid, force, err := keyArgs("activate-key", args)
	if err != nil {
		return err
	}
	_, db, err := openStore()
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.ActivateKey(context.Background(), kid, force); err != nil {
		return fmt.Errorf("activate-key %s: %w", kid, err)
	}
	slog.Info("signing key activated; restart the service to sign with it", "kid", kid)
	return nil
}

func retireKey(args []string) error {
	kid, force, err := keyArgs("retire-key", args)
	if err != nil {
		return err
	}
	_, db, err := openStore()
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.RetireKey(context.Background(), kid, force); err != nil {
		return fmt.Errorf("retire-key %s: %w", kid, err)
	}
	slog.Info("signing key retired; restart the service to drop it from the key set", "kid", kid)
	return nil
}

func keyArgs(cmd string, args []string) (kid string, force bool, err error) {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	f := fs.Bool("force", false, "skip the wait; for a compromised key, at the cost of breaking verifiers or tokens")
	if err := fs.Parse(args); err != nil {
		return "", false, err
	}
	if fs.NArg() != 1 {
		return "", false, fmt.Errorf("usage: %s [-force] <kid>", cmd)
	}
	return fs.Arg(0), *f, nil
}

// sealKeys encrypts whatever is still stored in the clear. It is idempotent, so
// a deploy script can run it every time.
func sealKeys() error {
	cfg, db, err := openStore()
	if err != nil {
		return err
	}
	defer db.Close()
	done, err := db.SealStoredKeys(context.Background(), sealer(cfg))
	if err != nil {
		return fmt.Errorf("seal-keys: %w", err)
	}
	if len(done) == 0 {
		slog.Info("every signing key was already sealed; nothing to do")
		return nil
	}
	slog.Info("signing keys sealed", "kids", done, "count", len(done))
	return nil
}

// unsealKeys is for rolling back to a release that cannot read sealed keys, and
// nothing else. It writes signing keys to the database in the clear.
func unsealKeys() error {
	cfg, db, err := openStore()
	if err != nil {
		return err
	}
	defer db.Close()
	done, err := db.UnsealStoredKeys(context.Background(), sealer(cfg))
	if err != nil {
		return fmt.Errorf("unseal-keys: %w", err)
	}
	slog.Warn("signing keys are now stored UNENCRYPTED; this is for a rollback only",
		"kids", done, "count", len(done))
	return nil
}

func sealer(cfg *provider.Config) keys.Sealer {
	return keys.SealerFor(cfg.CryptoKey, cfg.DevInsecure)
}
