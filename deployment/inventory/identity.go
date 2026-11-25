package inventory

import (
	"encoding/hex"
	"slices"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

const (
	addressLength       = 20
	uncompressedKeySize = 65
)

// canonicalSigner reduces a family's form of a signer to its lowercase 0x secp256k1 address. Families
// store the 20-byte address or the 65-byte key; other encodings go through the family's registered
// normalizer first. It returns "" when the value is neither.
func canonicalSigner(family, value string) string {
	raw, ok := decodeHex(shared.NormalizeAddress(family, strings.TrimSpace(value)))
	if !ok {
		return ""
	}
	switch len(raw) {
	case addressLength:
		return "0x" + hex.EncodeToString(raw)
	case uncompressedKeySize:
		pk, err := crypto.UnmarshalPubkey(raw)
		if err != nil {
			return ""
		}
		return strings.ToLower(crypto.PubkeyToAddress(*pk).Hex())
	default:
		return ""
	}
}

// uncompressedKey returns value as lowercase hex when it is a valid 65-byte secp256k1 public key.
func uncompressedKey(value string) (string, bool) {
	raw, ok := decodeHex(strings.TrimSpace(value))
	if !ok || len(raw) != uncompressedKeySize {
		return "", false
	}
	if _, err := crypto.UnmarshalPubkey(raw); err != nil {
		return "", false
	}
	return hex.EncodeToString(raw), true
}

func decodeHex(s string) ([]byte, bool) {
	raw, err := hex.DecodeString(strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X"))
	return raw, err == nil && len(raw) > 0
}

// resolver maps canonical signer addresses to NOPs, and NOPs to the nodes that sign and execute.
// It is derived from the NOP and node tables only, so a decoded inventory can rebuild it.
type resolver struct {
	aliases      map[string][]string // canonical address -> NOP aliases claiming it
	pubKeys      map[string]string   // canonical address -> uncompressed key from a NOP identity
	verifierNode map[string][]*Node  // NOP alias -> nodes that could sign
	scopedNode   map[verifierKey][]*Node
	executorNode map[string]*Node
}

// verifierKey binds a NOP's verifier node to the exact committee it signs for.
type verifierKey struct {
	alias     string
	qualifier string
}

func buildResolver(nops []NOP, nodes []Node) *resolver {
	r := &resolver{
		aliases:      make(map[string][]string),
		pubKeys:      make(map[string]string),
		verifierNode: make(map[string][]*Node),
		scopedNode:   make(map[verifierKey][]*Node),
		executorNode: make(map[string]*Node),
	}
	for _, nop := range nops {
		for _, id := range nop.Signers {
			if id.Address == "" {
				continue
			}
			if !slices.Contains(r.aliases[id.Address], nop.Alias) {
				r.aliases[id.Address] = append(r.aliases[id.Address], nop.Alias)
			}
			if key, ok := uncompressedKey(id.Value); ok && canonicalSigner(id.Family, id.Value) == id.Address {
				r.pubKeys[id.Address] = key
			}
		}
	}
	// Nodes are sorted by ID, so candidate order is deterministic.
	for i := range nodes {
		node := &nodes[i]
		if node.NOPAlias == "" {
			continue
		}
		if slices.Contains(node.Roles, RoleExecutor) && r.executorNode[node.NOPAlias] == nil {
			r.executorNode[node.NOPAlias] = node
		}
		if slices.Contains(node.Roles, RoleVerifier) {
			r.verifierNode[node.NOPAlias] = append(r.verifierNode[node.NOPAlias], node)
			for _, q := range node.VerifierQualifiers {
				k := verifierKey{node.NOPAlias, q}
				r.scopedNode[k] = append(r.scopedNode[k], node)
			}
		}
	}
	// With no verifier job on record (hand-proposed jobs), a role-less node named after the alias signs.
	for i := range nodes {
		node := &nodes[i]
		if node.NOPAlias != "" && len(node.Roles) == 0 && len(r.verifierNode[node.NOPAlias]) == 0 &&
			strings.EqualFold(node.Name, node.NOPAlias) {
			r.verifierNode[node.NOPAlias] = []*Node{node}
		}
	}
	return r
}

// verifierFor returns the exact node signing for alias in committee qualifier. ambiguous reports
// several candidates with no exact match; the caller records an issue instead of guessing.
func (r *resolver) verifierFor(alias, qualifier string) (node *Node, ambiguous bool) {
	scoped := r.scopedNode[verifierKey{alias, qualifier}]
	if len(scoped) == 1 {
		return scoped[0], false
	}
	if len(scoped) > 1 {
		return nil, true
	}
	if candidates := r.verifierNode[alias]; len(candidates) == 1 {
		return candidates[0], false
	} else if len(candidates) > 1 {
		return nil, true
	}
	return nil, false
}

// member resolves one signer, as its verifier chain's family stores it, to a committee member.
// The returned node backs role promotion; it is nil when the member is unresolved or ambiguous.
func (r *resolver) member(family, signer, qualifier string) (Member, *Node, bool) {
	addr := canonicalSigner(family, signer)
	if addr == "" {
		return Member{SignerAddress: strings.ToLower(strings.TrimSpace(signer))}, nil, false
	}
	m := Member{SignerAddress: addr, SignerPubKey: r.pubKeys[addr]}
	if aliases := r.aliases[addr]; len(aliases) == 1 {
		m.NOPAlias = aliases[0]
		node, ambiguous := r.verifierFor(m.NOPAlias, qualifier)
		if node != nil {
			m.NodeID = node.ID
			m.CSAKey = node.CSAKey
		}
		return m, node, ambiguous
	}
	return m, nil, false
}
