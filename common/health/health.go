package health

import (
	"net/http"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type ReadinessStatus string

const (
	Ready    ReadinessStatus = "ready"
	Degraded ReadinessStatus = "degraded"
	NotReady ReadinessStatus = "not_ready"
)

type LivenessStatus string

const (
	Alive LivenessStatus = "alive"
)

type LivenessResponse struct {
	Status LivenessStatus `json:"status"`
}

type ReadinessResponse struct {
	Status   ReadinessStatus  `json:"status"`
	Services []ServicesHealth `json:"services"`
}

type ServicesHealth struct {
	Name   string            `json:"name"`
	Status ReadinessStatus   `json:"status"`
	Error  string            `json:"error,omitempty"`
	Report map[string]string `json:"report,omitempty"`
}

func NewAliveResponse() LivenessResponse {
	return LivenessResponse{
		Status: Alive,
	}
}

func (r *LivenessResponse) StatusCode() int {
	if r.Status == Alive {
		return http.StatusOK
	}
	return http.StatusServiceUnavailable
}

// NotReady wins over Degraded, which wins over Ready.
func NewReadinessResponse(services []ServicesHealth) ReadinessResponse {
	status := Ready
	for _, component := range services {
		switch {
		case component.Status == NotReady:
			status = NotReady
		case component.Status == Degraded && status == Ready:
			status = Degraded
		}
	}

	return ReadinessResponse{
		Status:   status,
		Services: services,
	}
}

// StatusCode is 503 only when NotReady. Degraded services keep serving, so they stay in rotation.
func (r *ReadinessResponse) StatusCode() int {
	if r.Status == NotReady {
		return http.StatusServiceUnavailable
	}
	return http.StatusOK
}

// DegradedReporter is optional. A component that keeps running but is missing something
// (for example a skipped chain) implements it, and /health reports degraded without 503.
type DegradedReporter interface {
	Degraded() error
}

func CheckServiceHealth(
	reporter protocol.HealthReporter,
) ServicesHealth {
	var prettyError string
	status := Ready
	if err1 := reporter.Ready(); err1 != nil {
		status = NotReady
		prettyError = err1.Error()
	} else if dr, ok := reporter.(DegradedReporter); ok {
		if err2 := dr.Degraded(); err2 != nil {
			status = Degraded
			prettyError = err2.Error()
		}
	}

	errorReport := make(map[string]string)
	for k, v := range reporter.HealthReport() {
		if v != nil {
			errorReport[k] = v.Error()
		}
	}

	return ServicesHealth{
		Name:   reporter.Name(),
		Status: status,
		Error:  prettyError,
		Report: errorReport,
	}
}
