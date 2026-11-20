package tests

import (
	"testing"
	"time"
)

func WaitTimeout(*testing.T) time.Duration { return 10 * time.Second }
