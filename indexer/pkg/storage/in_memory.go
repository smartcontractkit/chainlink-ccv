package storage

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

var _ common.IndexerStorage = (*InMemoryStorage)(nil)

var ErrCCVDataNotFound = fmt.Errorf("CCV data not found")

type InMemoryStorage struct {
	ccvData *sync.Map
}

func NewInMemoryStorage() common.IndexerStorage {
	return &InMemoryStorage{
		ccvData: new(sync.Map),
	}
}

func (i *InMemoryStorage) GetCCVData(ctx context.Context, messageID types.Bytes32) ([]types.CCVData, error) {
	ccvData, ok := i.ccvData.Load(messageID)
	if !ok {
		return nil, ErrCCVDataNotFound
	}
	return ccvData.([]types.CCVData), nil
}

func (i *InMemoryStorage) QueryCCVDataByTimestamp(ctx context.Context, start, end int64) (map[string][]types.CCVData, error) {
	results := make(map[string][]types.CCVData)

	i.ccvData.Range(func(key, value any) bool {
		if ccvData, ok := value.([]types.CCVData); ok {
			if ccvData[0].Timestamp >= start && ccvData[0].Timestamp <= end {
				results[hex.EncodeToString(ccvData[0].MessageID[:])] = ccvData
			}
		}
		return true
	})

	return results, nil
}

func (i *InMemoryStorage) InsertCCVData(ctx context.Context, ccvData types.CCVData) error {
	storedCCVData, err := i.GetCCVData(ctx, ccvData.MessageID)
	if err != nil && errors.Is(err, ErrCCVDataNotFound) {
		i.ccvData.Store(ccvData.MessageID, []types.CCVData{ccvData})
	} else {
		storedCCVData = append(storedCCVData, ccvData)
		i.ccvData.Store(ccvData.MessageID, storedCCVData)
	}

	return nil
}
