package storage

import "errors"

var (
	ErrCCVDataNotFound  = errors.New("CCV data not found")
	ErrDuplicateCCVData = errors.New("duplicate CCV data")
	ErrMessageNotFound  = errors.New("message not found")
)
