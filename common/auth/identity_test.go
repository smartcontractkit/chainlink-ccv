package auth

import (
	"context"
	"testing"
)

func TestCreateCallerIdentity_SetsDefaultFieldsCorrectly(t *testing.T) {
	callerID := "user-123"
	ci := CreateCallerIdentity(callerID, true)

	if ci.CallerID != callerID {
		t.Fatalf("expected CallerID %q, got %q", callerID, ci.CallerID)
	}
	if !ci.IsAnonymous {
		t.Fatalf("expected IsAnonymous true, got false")
	}
}

func TestIdentityContext_RoundTrip_Succeeds(t *testing.T) {
	ctx := context.Background()
	ci := CreateCallerIdentity("user-99", false)

	ctx = ToContext(ctx, ci)
	got, ok := IdentityFromContext(ctx)
	if !ok {
		t.Fatalf("expected identity to be present in context")
	}
	if got != ci {
		t.Fatalf("expected pointer equality after round-trip")
	}
}

func TestIdentityFromContext_ReturnsFalseWhenNoIdentity(t *testing.T) {
	ctx := context.Background()
	if _, ok := IdentityFromContext(ctx); ok {
		t.Fatalf("expected no identity in empty context")
	}
}

func TestIdentityFromContext_ReturnsFalseWithWrongKeyType(t *testing.T) {
	//nolint:staticcheck // Using string key intentionally to verify behavior with wrong key type.
	ctx := context.WithValue(context.Background(), "identity", &CallerIdentity{CallerID: "x"})
	if _, ok := IdentityFromContext(ctx); ok {
		t.Fatalf("expected no identity when stored under wrong key type")
	}
}
