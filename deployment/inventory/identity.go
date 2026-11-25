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
	verifierNode map[string]*Node
	executorNode map[string]*Node
}

func buildResolver(nops []NOP, nodes []Node) *resolver {
	r := &resolver{
		aliases:      make(map[string][]string),
		pubKeys:      make(map[string]string),
		verifierNode: make(map[string]*Node),
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
	// Nodes are sorted by ID, so the first match wins deterministically.
	for i := range nodes {
		node := &nodes[i]
		if node.NOPAlias == "" {
			continue
		}
		if slices.Contains(node.Roles, RoleExecutor) && r.executorNode[node.NOPAlias] == nil {
			r.executorNode[node.NOPAlias] = node
		}
		if slices.Contains(node.Roles, RoleVerifier) && r.verifierNode[node.NOPAlias] == nil {
			r.verifierNode[node.NOPAlias] = node
		}
	}
	// With no verifier job on record (hand-proposed jobs), a role-less node named after the alias signs.
	for i := range nodes {
		node := &nodes[i]
		if node.NOPAlias != "" && len(node.Roles) == 0 && r.verifierNode[node.NOPAlias] == nil &&
			strings.EqualFold(node.Name, node.NOPAlias) {
			r.verifierNode[node.NOPAlias] = node
		}
	}
	return r
}

// member resolves one signer, as its verifier chain's family stores it, to a committee member.
func (r *resolver) member(family, signer string) Member {
	addr := canonicalSigner(family, signer)
	if addr == "" {
		return Member{SignerAddress: strings.ToLower(strings.TrimSpace(signer))}
	}
	m := Member{SignerAddress: addr, SignerPubKey: r.pubKeys[addr]}
	if aliases := r.aliases[addr]; len(aliases) == 1 {
		m.NOPAlias = aliases[0]
		if node := r.verifierNode[m.NOPAlias]; node != nil {
			m.NodeID = node.ID
			m.CSAKey = node.CSAKey
		}
	}
	return m
}
