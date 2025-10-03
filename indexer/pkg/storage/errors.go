package storage

import "fmt"

var (
	ErrCCVDataNotFound  = fmt.Errorf("CCV data not found")
	ErrDuplicateCCVData = fmt.Errorf("duplicate CCV data")
)
