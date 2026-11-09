//go:build conformance

// Command harness serves Portiko over HTTPS for the OpenID Foundation's
// conformance suite. It builds only with the conformance tag:
//
//	go run -tags conformance ./conformance/cmd/harness
//
// Configuration is by environment, with defaults for the Linux guest described
// in docs/conformance.md:
//
//	ISSUER        https://host.docker.internal:9443
//	LISTEN        :9443
//	DATABASE_URL  postgres://portiko:portiko@localhost:5432/portiko?sslmode=disable
//	REDIRECT_URI  https://localhost.emobix.co.uk:8443/test/a/portiko/callback
//
// The two clients' IDs and secrets match conformance/portiko.json.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Kolonnade/Portiko/conformance"
)

func main() {
	if err := run(); err != nil {
		slog.Error("conformance harness", "err", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	issuer := env("ISSUER", "https://host.docker.internal:9443")
	h, err := conformance.New(ctx, conformance.Config{
		Issuer:       issuer,
		DatabaseURL:  env("DATABASE_URL", "postgres://portiko:portiko@localhost:5432/portiko?sslmode=disable"),
		RedirectURIs: []string{env("REDIRECT_URI", "https://localhost.emobix.co.uk:8443/test/a/portiko/callback")},
		Clients: []conformance.Client{
			{ID: "conformance-1", Secret: "conformance-secret-1-c5d9a0e0f1b24e7a"},
			{ID: "conformance-2", Secret: "conformance-secret-2-8e3b6f0d2a7c41b9"},
		},
	})
	if err != nil {
		return err
	}
	defer h.Close()

	cert, err := selfSigned(issuer)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              env("LISTEN", ":9443"),
		Handler:           h,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shut)
	}()
	slog.Info("conformance harness ready", "issuer", issuer, "listen", srv.Addr, "account", conformance.Email)
	if err := srv.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	slog.Info("conformance harness stopped", "sign_ins", h.SignIns())
	return nil
}

// selfSigned makes a certificate for the issuer's host, generated per run: the
// suite does not verify the provider's certificate.
func selfSigned(issuer string) (tls.Certificate, error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return tls.Certificate{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: u.Hostname()},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{u.Hostname(), "localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
