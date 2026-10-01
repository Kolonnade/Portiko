package store

import (
	"context"
	"log/slog"
)

// Audit actions. Named constants rather than literals at the call sites, because
// these strings are what an investigation greps for months later: a typo makes
// an event invisible without making anything fail.
const (
	// AuditCredentialAdded records a passkey enrolled onto an account.
	AuditCredentialAdded = "credential.added"
	// AuditAccountRecovered records a passkey enrolled onto an account that
	// already existed, by way of reading its email — the recovery path.
	AuditAccountRecovered = "account.recovered"
	// AuditRefreshReuse records a rotated refresh token being presented again.
	AuditRefreshReuse = "refresh.reuse_detected"
)

// AuditEvent is one row of the authentication audit trail.
//
// IP and UserAgent are part of the event rather than looked up later: the whole
// value of the row to the person reading it afterwards is "was this me?", and
// that question is unanswerable without where the request came from.
type AuditEvent struct {
	UserID    *int64
	ClientID  string
	Action    string
	IP        string
	UserAgent string
	Detail    map[string]any
}

// Audit writes an audit row.
//
// A failure is logged, never returned: the audit trail must not be able to break
// the operation it records. A sign-in that fails because its audit row could not
// be written is a worse outcome than a missing row, and the log line is what
// catches a trail that has silently stopped.
func (d *DB) Audit(ctx context.Context, e AuditEvent) {
	if _, err := d.pool.Exec(ctx,
		`INSERT INTO auth_audit (user_id, client_id, action, ip, user_agent, detail)
		 VALUES ($1, NULLIF($2,''), $3, NULLIF($4,'')::inet, NULLIF($5,''), $6)`,
		e.UserID, e.ClientID, e.Action, e.IP, e.UserAgent, e.Detail); err != nil {
		slog.WarnContext(ctx, "writing audit row", "action", e.Action, "err", err)
	}
}
