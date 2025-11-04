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
	if ci.IsAdmin {
		t.Fatalf("expected IsAdmin false, got true")
	}
	if ci.EffectiveCallerID != callerID {
		t.Fatalf("expected EffectiveCallerID %q, got %q", callerID, ci.EffectiveCallerID)
	}
}

func TestCreateAdminCallerIdentity_SetsAdminFieldsCorrectly(t *testing.T) {
	callerID := "admin-1"
	ci := CreateAdminCallerIdentity(callerID)

	if ci.CallerID != callerID {
		t.Fatalf("expected CallerID %q, got %q", callerID, ci.CallerID)
	}
	if ci.IsAnonymous {
		t.Fatalf("expected IsAnonymous false, got true")
	}
	if !ci.IsAdmin {
		t.Fatalf("expected IsAdmin true, got false")
	}
	if ci.EffectiveCallerID != callerID {
		t.Fatalf("expected EffectiveCallerID %q, got %q", callerID, ci.EffectiveCallerID)
	}
}

func TestCallerIdentity_SetOnBehalfOf_Behavior(t *testing.T) {
	cases := []struct {
		name                string
		isAdmin             bool
		initialEffectiveID  string
		onBehalfOf          string
		expectedEffectiveID string
	}{
		{
			name:                "admin_should_update_effective_caller_id",
			isAdmin:             true,
			initialEffectiveID:  "admin-1",
			onBehalfOf:          "user-42",
			expectedEffectiveID: "user-42",
		},
		{
			name:                "non_admin_should_not_update_effective_caller_id",
			isAdmin:             false,
			initialEffectiveID:  "user-1",
			onBehalfOf:          "user-42",
			expectedEffectiveID: "user-1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var ci *CallerIdentity
			if tc.isAdmin {
				ci = CreateAdminCallerIdentity(tc.initialEffectiveID)
			} else {
				ci = CreateCallerIdentity(tc.initialEffectiveID, false)
			}

			ci.SetOnBehalfOf(tc.onBehalfOf)

			if ci.EffectiveCallerID != tc.expectedEffectiveID {
				t.Fatalf("expected EffectiveCallerID %q, got %q", tc.expectedEffectiveID, ci.EffectiveCallerID)
			}
		})
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
