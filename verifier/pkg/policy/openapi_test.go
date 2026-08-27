package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// specPath is the published endpoint contract, relative to this package.
const specPath = "../../policy_hook_openapi_v1.yaml"

type openAPISchema struct {
	Properties map[string]struct {
		Enum []string `yaml:"enum"`
	} `yaml:"properties"`
	Required []string `yaml:"required"`
	Type     string   `yaml:"type"`
}

type openAPISpec struct {
	OpenAPI    string `yaml:"openapi"`
	Components struct {
		Schemas map[string]openAPISchema `yaml:"schemas"`
	} `yaml:"components"`
	Paths map[string]map[string]struct {
		OperationID string `yaml:"operationId"`
	} `yaml:"paths"`
}

func loadSpec(t *testing.T) openAPISpec {
	t.Helper()

	raw, err := os.ReadFile(filepath.Clean(specPath))
	require.NoError(t, err, "the published contract must live at %s", specPath)

	var spec openAPISpec
	require.NoError(t, yaml.Unmarshal(raw, &spec))
	return spec
}

// jsonFields returns the JSON field names of a struct, and the subset that is required (a field
// without omitempty is always present on the wire).
func jsonFields(t *testing.T, v any) (all, required []string) {
	t.Helper()

	typ := reflect.TypeOf(v)
	require.Equal(t, reflect.Struct, typ.Kind())

	for i := range typ.NumField() {
		tag := typ.Field(i).Tag.Get("json")
		require.NotEmpty(t, tag, "%s.%s has no json tag, so it cannot be checked against the spec",
			typ.Name(), typ.Field(i).Name)

		parts := strings.Split(tag, ",")
		name := parts[0]
		if name == "-" {
			continue
		}
		all = append(all, name)
		if !slices.Contains(parts[1:], "omitempty") {
			required = append(required, name)
		}
	}
	slices.Sort(all)
	slices.Sort(required)
	return all, required
}

// TestOpenAPISpecMatchesContract keeps the published spec and the Go types that implement it from
// drifting. Operators build against the spec, so a field added to the Go struct without a spec
// entry (or the reverse) is a broken contract, not a cosmetic mismatch.
func TestOpenAPISpecMatchesContract(t *testing.T) {
	spec := loadSpec(t)

	assert.Equal(t, "3.0.3", spec.OpenAPI, "the program's OpenAPI documents are 3.0.3")

	cases := []struct {
		value      any
		schemaName string
	}{
		{schemaName: "EvaluateRequest", value: EvaluateRequest{}},
		{schemaName: "EvaluateResponse", value: EvaluateResponse{}},
		{schemaName: "Message", value: MessageV1{}},
		{schemaName: "TokenTransfer", value: TokenTransferV1{}},
	}

	for _, tc := range cases {
		t.Run(tc.schemaName, func(t *testing.T) {
			schema, ok := spec.Components.Schemas[tc.schemaName]
			require.True(t, ok, "spec has no schema %q", tc.schemaName)
			assert.Equal(t, "object", schema.Type)

			wantAll, wantRequired := jsonFields(t, tc.value)

			gotAll := make([]string, 0, len(schema.Properties))
			for name := range schema.Properties {
				gotAll = append(gotAll, name)
			}
			slices.Sort(gotAll)
			assert.Equal(t, wantAll, gotAll, "spec properties for %s differ from the Go struct", tc.schemaName)

			gotRequired := slices.Clone(schema.Required)
			slices.Sort(gotRequired)
			assert.Equal(t, wantRequired, gotRequired,
				"spec required fields for %s differ from the Go struct's non-omitempty fields", tc.schemaName)
		})
	}
}

func TestOpenAPISpecEnums(t *testing.T) {
	spec := loadSpec(t)

	decision := spec.Components.Schemas["EvaluateResponse"].Properties["decision"]
	assert.Equal(t, []string{string(DecisionPass), string(DecisionFail)}, decision.Enum,
		"the spec's verdicts must be exactly the two the verifier accepts")

	schemaVersion := spec.Components.Schemas["EvaluateRequest"].Properties["schema_version"]
	assert.Equal(t, []string{SchemaVersion}, schemaVersion.Enum)
}

func TestOpenAPISpecDeclaresEvaluateOperation(t *testing.T) {
	spec := loadSpec(t)

	operationIDs := make([]string, 0, len(spec.Paths))
	for _, methods := range spec.Paths {
		for method, op := range methods {
			assert.Equal(t, "post", method, "the hook is a POST-only contract")
			operationIDs = append(operationIDs, op.OperationID)
		}
	}
	assert.Equal(t, []string{"policy-evaluate"}, operationIDs)
}

// The verifier must be able to read a response written exactly as the spec's example shows.
func TestEvaluateResponse_DecodesSpecShape(t *testing.T) {
	var pass EvaluateResponse
	require.NoError(t, json.Unmarshal([]byte(`{"decision":"PASS"}`), &pass))
	assert.Equal(t, DecisionPass, pass.Decision)

	var fail EvaluateResponse
	require.NoError(t, json.Unmarshal([]byte(`{"decision":"FAIL","reason":"sanctioned sender"}`), &fail))
	assert.Equal(t, DecisionFail, fail.Decision)
	assert.Equal(t, "sanctioned sender", fail.Reason)
}
