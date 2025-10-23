package logasserter

import (
	"time"
)

type LogStage struct {
	Name       string
	Service    string
	LogPattern string
}

type InstanceLog struct {
	InstanceName string
	Timestamp    time.Time
	LogLine      string
	Labels       map[string]string
}
