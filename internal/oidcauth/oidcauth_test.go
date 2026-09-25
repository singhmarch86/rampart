package oidcauth

import (
	"reflect"
	"testing"
)

func TestExtractRolesKeycloakNested(t *testing.T) {
	claims := map[string]any{
		"realm_access": map[string]any{
			"roles": []any{"admin", "viewer"},
		},
	}
	got := extractRoles(claims, "realm_access.roles")
	want := []string{"admin", "viewer"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestExtractRolesFlatArray(t *testing.T) {
	claims := map[string]any{"roles": []any{"editor"}}
	got := extractRoles(claims, "roles")
	if !reflect.DeepEqual(got, []string{"editor"}) {
		t.Fatalf("got %v", got)
	}
}

func TestExtractRolesMissingPath(t *testing.T) {
	claims := map[string]any{"other": "value"}
	if got := extractRoles(claims, "realm_access.roles"); got != nil {
		t.Fatalf("expected nil for missing path, got %v", got)
	}
}

func TestExtractRolesWrongType(t *testing.T) {
	claims := map[string]any{"realm_access": "not an object"}
	if got := extractRoles(claims, "realm_access.roles"); got != nil {
		t.Fatalf("expected nil when path segment isn't an object, got %v", got)
	}
}

func TestExtractRolesEmptyPath(t *testing.T) {
	if got := extractRoles(map[string]any{"roles": []any{"a"}}, ""); got != nil {
		t.Fatalf("expected nil for empty path, got %v", got)
	}
}

func TestHasAnyRoleEmptyRequiredMeansAnyoneAllowed(t *testing.T) {
	if !hasAnyRole(nil, nil) {
		t.Fatal("expected empty required-roles list to allow a user with no roles")
	}
}

func TestHasAnyRoleMatch(t *testing.T) {
	if !hasAnyRole([]string{"viewer", "editor"}, []string{"admin", "editor"}) {
		t.Fatal("expected match on overlapping role")
	}
}

func TestHasAnyRoleNoMatch(t *testing.T) {
	if hasAnyRole([]string{"viewer"}, []string{"admin"}) {
		t.Fatal("expected no match")
	}
}
