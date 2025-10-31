package auth

import "context"

type contextKey string

const identityKey contextKey = "identity"

type CallerIdentity struct {
	CallerID          string
	IsAnonymous       bool
	IsAdmin           bool
	EffectiveCallerID string // The actual caller ID to use for operations (for admin on-behalf-of)
}

func CreateCallerIdentity(callerID string, isAnonymous bool) *CallerIdentity {
	return &CallerIdentity{
		CallerID:          callerID,
		IsAnonymous:       isAnonymous,
		IsAdmin:           false,
		EffectiveCallerID: callerID, // Default to actual caller
	}
}

// CreateAdminCallerIdentity creates a caller identity for admin clients.
func CreateAdminCallerIdentity(callerID string) *CallerIdentity {
	return &CallerIdentity{
		CallerID:          callerID,
		IsAnonymous:       false,
		IsAdmin:           true,
		EffectiveCallerID: callerID, // Default to actual caller
	}
}

// SetOnBehalfOf sets the effective caller ID for admin operations.
func (c *CallerIdentity) SetOnBehalfOf(targetClientID string) {
	if c.IsAdmin {
		c.EffectiveCallerID = targetClientID
	}
}

func IdentityFromContext(ctx context.Context) (*CallerIdentity, bool) {
	if v := ctx.Value(identityKey); v != nil {
		if identity, ok := v.(*CallerIdentity); ok {
			return identity, true
		}
	}
	return nil, false
}

func ToContext(ctx context.Context, identity *CallerIdentity) context.Context {
	return context.WithValue(ctx, identityKey, identity)
}
