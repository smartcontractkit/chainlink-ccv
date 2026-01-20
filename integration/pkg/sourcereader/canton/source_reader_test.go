package canton

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
	"github.com/smartcontractkit/freeport"
)

func TestCantonSourceReader_LatestAndFinalizedBlock(t *testing.T) {
	port := freeport.GetOne(t)
	bcInput := &blockchain.Input{
		Type:                     blockchain.TypeCanton,
		Port:                     strconv.Itoa(port),
		ContainerName:            "test-canton",
		NumberOfCantonValidators: 1,
	}
	bcOutput, err := blockchain.NewBlockchainNetwork(bcInput)
	require.NoError(t, err)

	jwt := bcOutput.NetworkSpecificData.CantonEndpoints.Participants[0].JWT
	require.NotEmpty(t, jwt)

	grpcURL := bcOutput.NetworkSpecificData.CantonEndpoints.Participants[0].GRPCLedgerAPIURL
	sourceReader, err := NewSourceReader(
		grpcURL,
		jwt,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	latest, finalized, err := sourceReader.LatestAndFinalizedBlock(t.Context())
	require.NoError(t, err)
	require.NotNil(t, latest)
	require.NotNil(t, finalized)
	t.Logf("latest block: %d", latest.Number)
	t.Logf("finalized block: %d", finalized.Number)
}
