package profile

import "context"

// Presentation is how an account is shown to the sites it signs in to. It
// travels in tokens under the profile scope.
type Presentation struct {
	Name      string         // the "name" claim
	Avatar    string         // the "avatar" claim; the built-in source uses an emoji
	UpdatedAt int64          // the "updated_at" claim: this presentation's version, Unix seconds
	Extra     map[string]any // further claims under the profile scope
}

// Source supplies an account's presentation.
//
// This is Portiko's extension point for what a product means by a profile. The
// built-in source is a display name and an emoji avatar kept by Portiko itself;
// a deployment can replace it with anything that can answer for a subject.
//
// UpdatedAt matters more than it looks: sites apply a change only when its
// version is newer than the one they hold, so a Source must bump it whenever
// anything it returns changes, and never move it backwards.
type Source interface {
	Presentation(ctx context.Context, subject string) (Presentation, error)
}
