package auth

import "context"

type contextKey string

const identityKey contextKey = "identity"

type CallerIdentity struct {
	CallerID    string
	IsAnonymous bool
}

func CreateCallerIdentity(callerID string, isAnonymous bool) *CallerIdentity {
	return &CallerIdentity{
		CallerID:    callerID,
		IsAnonymous: isAnonymous,
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
