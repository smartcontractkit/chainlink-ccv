package registration

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"
	"github.com/smartcontractkit/chainlink-protos/job-distributor/v1/shared/ptypes"
)

func TestRegisterNewNodeAndIdempotentRerun(t *testing.T) {
	t.Parallel()
	client := newFakeJD()
	spec := testNodeSpec("verifier-0")
	key := validCSAKey(1)

	registered, err := Register(t.Context(), client, StaticCSAKeyProvider(key), spec)
	require.NoError(t, err)
	require.Equal(t, StatusRegistered, registered.Status)
	require.NotEmpty(t, registered.NodeID)
	require.Equal(t, 1, client.mutationCount())

	stored := client.snapshotNodes()[registered.NodeID]
	require.Equal(t, spec.Name, stored.Name)
	require.Equal(t, key, stored.PublicKey)
	require.Equal(t, map[string]string{
		"product": "ccv", "environment": "devenv", "type": "plugin", "target": spec.Name,
	}, labelMap(stored.Labels))
	require.Equal(t, []string{"environment", "product", "target", "type"}, labelKeys(stored.Labels))

	existing, err := Register(t.Context(), client, StaticCSAKeyProvider(key), spec)
	require.NoError(t, err)
	require.Equal(t, registered.NodeID, existing.NodeID)
	require.Equal(t, StatusExisting, existing.Status)
	require.False(t, existing.LabelsReconciled)
	require.Equal(t, 1, client.mutationCount())
}

func TestRegisterBootstrapLabel(t *testing.T) {
	t.Parallel()
	client := newFakeJD()
	spec := testNodeSpec("bootstrap-0")
	spec.IsBootstrap = true
	result, err := Register(t.Context(), client, StaticCSAKeyProvider(validCSAKey(1)), spec)
	require.NoError(t, err)
	require.Equal(t, "bootstrap", labelMap(client.snapshotNodes()[result.NodeID].Labels)["type"])
}

func TestRegisterReconcilesLabelsWithoutChangingIdentity(t *testing.T) {
	t.Parallel()
	client := newFakeJD()
	spec := testNodeSpec("verifier-0")
	key := validCSAKey(1)
	client.addNode(&nodev1.Node{
		Id: "existing-id", Name: spec.Name, PublicKey: key,
		Labels: sortedLabels(map[string]string{"unrelated": "keep", "product": "wrong"}),
	})

	result, err := Register(t.Context(), client, StaticCSAKeyProvider(key), spec)
	require.NoError(t, err)
	require.Equal(t, "existing-id", result.NodeID)
	require.Equal(t, StatusExisting, result.Status)
	require.True(t, result.LabelsReconciled)
	require.Equal(t, 1, client.mutationCount())

	stored := client.snapshotNodes()[result.NodeID]
	require.Equal(t, spec.Name, stored.Name)
	require.Equal(t, key, stored.PublicKey)
	require.Equal(t, map[string]string{
		"product": "ccv", "environment": "devenv", "type": "plugin", "target": spec.Name, "unrelated": "keep",
	}, labelMap(stored.Labels))

	rerun, err := Register(t.Context(), client, StaticCSAKeyProvider(key), spec)
	require.NoError(t, err)
	require.False(t, rerun.LabelsReconciled)
	require.Equal(t, 1, client.mutationCount())
}

func TestRegisterRejectsConflictsWithoutMutation(t *testing.T) {
	t.Parallel()
	t.Run("same key different name", func(t *testing.T) {
		t.Parallel()
		client := newFakeJD()
		key := validCSAKey(1)
		client.addNode(nodeForSpec(testNodeSpec("other-name"), key, "existing-id"))
		before := client.snapshotNodes()
		_, err := Register(t.Context(), client, StaticCSAKeyProvider(key), testNodeSpec("desired-name"))
		require.ErrorContains(t, err, "already registered as")
		require.Zero(t, client.mutationCount())
		require.Equal(t, before, client.snapshotNodes())
	})
	t.Run("same name different key", func(t *testing.T) {
		t.Parallel()
		client := newFakeJD()
		spec := testNodeSpec("verifier-0")
		client.addNode(nodeForSpec(spec, validCSAKey(1), "existing-id"))
		before := client.snapshotNodes()
		_, err := Register(t.Context(), client, StaticCSAKeyProvider(validCSAKey(2)), spec)
		require.ErrorContains(t, err, "different CSA key")
		require.Zero(t, client.mutationCount())
		require.Equal(t, before, client.snapshotNodes())
	})
}

func TestRegisterProductionWrappedNotFound(t *testing.T) {
	t.Parallel()
	client := newFakeJD()
	client.getNodeFunc = func(context.Context, *nodev1.GetNodeRequest) (*nodev1.GetNodeResponse, error) {
		return nil, status.Error(codes.Internal, "rpc error: code = NotFound desc = node with identifier abc does not exist")
	}
	result, err := Register(t.Context(), client, StaticCSAKeyProvider(validCSAKey(1)), testNodeSpec("verifier-0"))
	require.NoError(t, err)
	require.Equal(t, StatusRegistered, result.Status)
}

func TestRegisterLookupFailures(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name string
		err  error
	}{
		{name: "internal", err: status.Error(codes.Internal, "database unavailable")},
		{name: "unauthenticated", err: status.Error(codes.Unauthenticated, "invalid token")},
		{name: "plain", err: errors.New("transport failed")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			client := newFakeJD()
			client.getNodeFunc = func(context.Context, *nodev1.GetNodeRequest) (*nodev1.GetNodeResponse, error) {
				return nil, tt.err
			}
			_, err := Register(t.Context(), client, StaticCSAKeyProvider(validCSAKey(1)), testNodeSpec("verifier-0"))
			require.Error(t, err)
			require.Zero(t, client.mutationCount())
		})
	}
}

func TestRegisterResponseValidation(t *testing.T) {
	t.Parallel()
	spec := testNodeSpec("verifier-0")
	key := validCSAKey(1)
	tests := []struct {
		name      string
		configure func(*fakeJD)
		want      string
	}{
		{
			name: "nil get response",
			configure: func(client *fakeJD) {
				client.getNodeFunc = func(context.Context, *nodev1.GetNodeRequest) (*nodev1.GetNodeResponse, error) { return nil, nil }
			},
			want: "invalid JD response",
		},
		{
			name: "empty get response",
			configure: func(client *fakeJD) {
				client.getNodeFunc = func(context.Context, *nodev1.GetNodeRequest) (*nodev1.GetNodeResponse, error) {
					return &nodev1.GetNodeResponse{}, nil
				}
			},
			want: "invalid JD response",
		},
		{
			name: "nil list response",
			configure: func(client *fakeJD) {
				client.listNodesFunc = func(context.Context, *nodev1.ListNodesRequest) (*nodev1.ListNodesResponse, error) { return nil, nil }
			},
			want: "invalid JD response",
		},
		{
			name: "list failure",
			configure: func(client *fakeJD) {
				client.listNodesFunc = func(context.Context, *nodev1.ListNodesRequest) (*nodev1.ListNodesResponse, error) {
					return nil, errors.New("list failed")
				}
			},
			want: "list failed",
		},
		{
			name: "nil register response",
			configure: func(client *fakeJD) {
				client.registerFunc = func(context.Context, *nodev1.RegisterNodeRequest) (*nodev1.RegisterNodeResponse, error) {
					return nil, nil
				}
			},
			want: "invalid JD response",
		},
		{
			name: "empty registered ID",
			configure: func(client *fakeJD) {
				client.registerFunc = func(_ context.Context, req *nodev1.RegisterNodeRequest) (*nodev1.RegisterNodeResponse, error) {
					return &nodev1.RegisterNodeResponse{Node: &nodev1.Node{Name: req.Name, PublicKey: req.PublicKey}}, nil
				}
			},
			want: "invalid JD response",
		},
		{
			name: "wrong registered node",
			configure: func(client *fakeJD) {
				client.registerFunc = func(context.Context, *nodev1.RegisterNodeRequest) (*nodev1.RegisterNodeResponse, error) {
					return &nodev1.RegisterNodeResponse{Node: &nodev1.Node{Id: "node-1", Name: "other", PublicKey: key}}, nil
				}
			},
			want: "different node",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			client := newFakeJD()
			tt.configure(client)
			_, err := Register(t.Context(), client, StaticCSAKeyProvider(key), spec)
			require.ErrorContains(t, err, tt.want)
		})
	}
}

func TestRegisterUpdateResponseValidation(t *testing.T) {
	t.Parallel()
	client := newFakeJD()
	spec := testNodeSpec("verifier-0")
	key := validCSAKey(1)
	client.addNode(&nodev1.Node{Id: "existing-id", Name: spec.Name, PublicKey: key})
	client.updateNodeFunc = func(context.Context, *nodev1.UpdateNodeRequest) (*nodev1.UpdateNodeResponse, error) {
		return &nodev1.UpdateNodeResponse{Node: &nodev1.Node{Id: "other-id"}}, nil
	}
	_, err := Register(t.Context(), client, StaticCSAKeyProvider(key), spec)
	require.ErrorContains(t, err, "invalid JD response after reconciling")
}

func TestRegisterInputValidation(t *testing.T) {
	t.Parallel()
	client := newFakeJD()
	spec := testNodeSpec("verifier-0")
	_, err := Register(t.Context(), nil, StaticCSAKeyProvider(validCSAKey(1)), spec)
	require.ErrorContains(t, err, "JD client is required")
	_, err = Register(t.Context(), client, nil, spec)
	require.ErrorContains(t, err, "provider is required")

	for _, tt := range []struct {
		name string
		spec NodeSpec
		key  string
		want string
	}{
		{name: "missing name", spec: NodeSpec{Product: "ccv", Environment: "devenv"}, key: validCSAKey(1), want: "required"},
		{name: "missing product", spec: NodeSpec{Name: "node", Environment: "devenv"}, key: validCSAKey(1), want: "required"},
		{name: "missing environment", spec: NodeSpec{Name: "node", Product: "ccv"}, key: validCSAKey(1), want: "required"},
		{name: "empty label", spec: NodeSpec{Name: "node", Product: "ccv", Environment: "devenv", Labels: map[string]string{" ": "x"}}, key: validCSAKey(1), want: "empty label"},
		{name: "managed label", spec: NodeSpec{Name: "node", Product: "ccv", Environment: "devenv", Labels: map[string]string{"type": "plugin"}}, key: validCSAKey(1), want: "managed"},
		{name: "non hex key", spec: testNodeSpec("node"), key: "not-hex", want: "hex encoded"},
		{name: "short key", spec: testNodeSpec("node"), key: "0102", want: "32 bytes"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Register(t.Context(), client, StaticCSAKeyProvider(tt.key), tt.spec)
			require.ErrorContains(t, err, tt.want)
		})
	}

	_, err = Register(t.Context(), client, providerFunc(func(context.Context) (string, error) {
		return "", errors.New("key unavailable")
	}), spec)
	require.ErrorContains(t, err, "key unavailable")
}

func TestIsJDNotFound(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", want: false},
		{name: "direct", err: status.Error(codes.NotFound, "missing"), want: true},
		{name: "wrapped", err: fmt.Errorf("lookup: %w", status.Error(codes.NotFound, "missing")), want: true},
		{name: "production nested", err: status.Error(codes.Internal, "rpc error: code = NotFound desc = node with identifier abc does not exist"), want: true},
		{name: "other internal", err: status.Error(codes.Internal, "connection refused"), want: false},
		{name: "unauthenticated", err: status.Error(codes.Unauthenticated, "invalid token"), want: false},
		{name: "plain", err: errors.New("missing"), want: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, isJDNotFound(tt.err))
		})
	}
}

func labelKeys(labels []*ptypes.Label) []string {
	keys := make([]string, 0, len(labels))
	for _, label := range labels {
		keys = append(keys, label.Key)
	}
	return keys
}

type providerFunc func(context.Context) (string, error)

func (f providerFunc) CSAKey(ctx context.Context) (string, error) {
	return f(ctx)
}

func TestRegisterRejectsLegacyAndOutOfScopeNameConflicts(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name   string
		labels map[string]string
	}{
		{name: "legacy unlabeled node"},
		{name: "different environment", labels: map[string]string{"product": "ccv", "environment": "other"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			client := newFakeJD()
			spec := testNodeSpec("verifier-0")
			existing := nodeForSpec(spec, validCSAKey(1), "existing-id")
			existing.Labels = sortedLabels(tt.labels)
			client.addNode(existing)
			before := client.snapshotNodes()

			_, err := Register(t.Context(), client, StaticCSAKeyProvider(validCSAKey(2)), spec)
			require.ErrorContains(t, err, "different CSA key")
			require.Zero(t, client.mutationCount())
			require.Equal(t, before, client.snapshotNodes())
		})
	}
}

func TestRegisterAlreadyExistsRace(t *testing.T) {
	t.Parallel()
	client := newFakeJD()
	spec := testNodeSpec("verifier-0")
	key := validCSAKey(1)
	client.registerFunc = func(context.Context, *nodev1.RegisterNodeRequest) (*nodev1.RegisterNodeResponse, error) {
		client.addNode(nodeForSpec(spec, key, "concurrent-id"))
		return nil, status.Error(codes.AlreadyExists, "node already exists")
	}

	result, err := Register(t.Context(), client, StaticCSAKeyProvider(key), spec)
	require.NoError(t, err)
	require.Equal(t, "concurrent-id", result.NodeID)
	require.Equal(t, StatusExisting, result.Status)
}

func TestRegisterValidatesResponseLabels(t *testing.T) {
	t.Parallel()
	t.Run("register response missing labels", func(t *testing.T) {
		t.Parallel()
		client := newFakeJD()
		spec := testNodeSpec("verifier-0")
		key := validCSAKey(1)
		client.registerFunc = func(_ context.Context, req *nodev1.RegisterNodeRequest) (*nodev1.RegisterNodeResponse, error) {
			return &nodev1.RegisterNodeResponse{Node: &nodev1.Node{Id: "node-1", Name: req.Name, PublicKey: req.PublicKey}}, nil
		}
		_, err := Register(t.Context(), client, StaticCSAKeyProvider(key), spec)
		require.ErrorContains(t, err, "requested labels")
	})
	t.Run("update response missing labels", func(t *testing.T) {
		t.Parallel()
		client := newFakeJD()
		spec := testNodeSpec("verifier-0")
		key := validCSAKey(1)
		client.addNode(&nodev1.Node{Id: "existing-id", Name: spec.Name, PublicKey: key})
		client.updateNodeFunc = func(_ context.Context, req *nodev1.UpdateNodeRequest) (*nodev1.UpdateNodeResponse, error) {
			return &nodev1.UpdateNodeResponse{Node: &nodev1.Node{Id: req.Id, Name: req.Name, PublicKey: req.PublicKey}}, nil
		}
		_, err := Register(t.Context(), client, StaticCSAKeyProvider(key), spec)
		require.ErrorContains(t, err, "invalid JD response after reconciling")
	})
}

func TestIsJDAlreadyExists(t *testing.T) {
	t.Parallel()
	require.True(t, isJDAlreadyExists(status.Error(codes.AlreadyExists, "duplicate")))
	require.True(t, isJDAlreadyExists(status.Error(codes.Internal, "rpc error: code = AlreadyExists desc = duplicate")))
	require.False(t, isJDAlreadyExists(status.Error(codes.Internal, "database unavailable")))
	require.False(t, isJDAlreadyExists(nil))
}
