package aggregator_config

import (
	"strconv"
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/committee_verifier"
	"github.com/smartcontractkit/chainlink-ccv/deployments"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

const (
	aggregatorTestChainSel      = uint64(16015286601757825753)
	aggregatorTestCommitteeQual = "default"
	aggregatorVerifierOtherAddr = "0x1111111111111111111111111111111111111111"
	aggregatorVerifier1_7_0Addr = "0x958F44bbA928E294D5199870e330c4f30E5E5Ed4"
)

var otherVersion = semver.MustParse("10.0.0")

func TestBuildDestinationVerifiers_ResolvesCommitteeVerifier1_7_0WhenDatastoreHasBothVersions(t *testing.T) {
	ds := datastore.NewMemoryDataStore()
	chainSel := aggregatorTestChainSel
	qualifier := aggregatorTestCommitteeQual

	require.NoError(t, ds.Addresses().Add(datastore.AddressRef{
		ChainSelector: chainSel,
		Type:          datastore.ContractType(committee_verifier.ResolverType),
		Qualifier:     qualifier,
		Address:       aggregatorVerifierOtherAddr,
		Version:       otherVersion,
	}))
	require.NoError(t, ds.Addresses().Add(datastore.AddressRef{
		ChainSelector: chainSel,
		Type:          datastore.ContractType(committee_verifier.ResolverType),
		Qualifier:     qualifier,
		Address:       aggregatorVerifier1_7_0Addr,
		Version:       committee_verifier.Version,
	}))
	require.NoError(t, ds.Addresses().Add(datastore.AddressRef{
		ChainSelector: chainSel,
		Type:          datastore.ContractType(committee_verifier.ContractType),
		Qualifier:     qualifier,
		Address:       aggregatorVerifierOtherAddr,
		Version:       otherVersion,
	}))
	require.NoError(t, ds.Addresses().Add(datastore.AddressRef{
		ChainSelector: chainSel,
		Type:          datastore.ContractType(committee_verifier.ContractType),
		Qualifier:     qualifier,
		Address:       aggregatorVerifier1_7_0Addr,
		Version:       committee_verifier.Version,
	}))

	destVerifiers, err := buildDestinationVerifiers(ds.Seal(), qualifier, []uint64{chainSel})
	require.NoError(t, err)
	addr, ok := destVerifiers[strconv.FormatUint(chainSel, 10)]
	require.True(t, ok)
	assert.Equal(t, aggregatorVerifier1_7_0Addr, addr, "buildDestinationVerifiers must resolve CommitteeVerifier 1.7.0 when both versions exist")
}

func TestBuildQuorumConfigsFromOnChain_ResolvesCommitteeVerifier1_7_0WhenDatastoreHasBothVersions(t *testing.T) {
	ds := datastore.NewMemoryDataStore()
	chainSel := aggregatorTestChainSel
	qualifier := aggregatorTestCommitteeQual

	require.NoError(t, ds.Addresses().Add(datastore.AddressRef{
		ChainSelector: chainSel,
		Type:          datastore.ContractType(committee_verifier.ResolverType),
		Qualifier:     qualifier,
		Address:       aggregatorVerifierOtherAddr,
		Version:       otherVersion,
	}))
	require.NoError(t, ds.Addresses().Add(datastore.AddressRef{
		ChainSelector: chainSel,
		Type:          datastore.ContractType(committee_verifier.ResolverType),
		Qualifier:     qualifier,
		Address:       aggregatorVerifier1_7_0Addr,
		Version:       committee_verifier.Version,
	}))
	require.NoError(t, ds.Addresses().Add(datastore.AddressRef{
		ChainSelector: chainSel,
		Type:          datastore.ContractType(committee_verifier.ContractType),
		Qualifier:     qualifier,
		Address:       aggregatorVerifierOtherAddr,
		Version:       otherVersion,
	}))
	require.NoError(t, ds.Addresses().Add(datastore.AddressRef{
		ChainSelector: chainSel,
		Type:          datastore.ContractType(committee_verifier.ContractType),
		Qualifier:     qualifier,
		Address:       aggregatorVerifier1_7_0Addr,
		Version:       committee_verifier.Version,
	}))

	committeeStates := []*deployments.OnChainCommitteeState{
		{
			Qualifier:     qualifier,
			ChainSelector: chainSel,
			SignatureConfigs: []deployments.OnChainSignatureConfig{
				{
					SourceChainSelector: chainSel,
					Signers:             []common.Address{common.HexToAddress("0xAbC")},
					Threshold:           1,
				},
			},
		},
	}

	quorumConfigs, err := buildQuorumConfigsFromOnChain(ds.Seal(), committeeStates, qualifier, []uint64{chainSel})
	require.NoError(t, err)
	qc, ok := quorumConfigs[strconv.FormatUint(chainSel, 10)]
	require.True(t, ok)
	assert.Equal(t, aggregatorVerifier1_7_0Addr, qc.SourceVerifierAddress, "buildQuorumConfigsFromOnChain must resolve CommitteeVerifier 1.7.0 when both versions exist")
}
