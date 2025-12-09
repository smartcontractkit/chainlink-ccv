package health

import (
	"net/http"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type ServiceStatus string

const (
	Ready    ServiceStatus = "ready"
	NotReady ServiceStatus = "not_ready"
)

type ServiceLiveness string

const (
	Alive ServiceLiveness = "alive"
)

type LivenessResponse struct {
	Status ServiceLiveness `json:"status"`
}

type ReadinessResponse struct {
	Status   ServiceStatus    `json:"status"`
	Services []ServicesHealth `json:"services"`
}

type ServicesHealth struct {
	Name   string           `json:"name"`
	Status ServiceStatus    `json:"status"`
	Error  string           `json:"error,omitempty"`
	Report map[string]error `json:"report,omitempty"`
}

func NewLivenessResponse() LivenessResponse {
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

func NewReadinessResponse(services []ServicesHealth) ReadinessResponse {
	status := Ready
	for _, component := range services {
		if component.Status == NotReady {
			status = NotReady
		}
	}

	return ReadinessResponse{
		Status:   status,
		Services: services,
	}
}

func (r *ReadinessResponse) StatusCode() int {
	if r.Status == Ready {
		return http.StatusOK
	}
	return http.StatusServiceUnavailable
}

func NewServiceHealth(
	reporter protocol.HealthReporter,
) ServicesHealth {
	var prettyError string
	status := Ready
	if err1 := reporter.Ready(); err1 != nil {
		status = NotReady
		prettyError = err1.Error()
	}

	return ServicesHealth{
		Name:   reporter.Name(),
		Status: status,
		Error:  prettyError,
		Report: reporter.HealthReport(),
	}
}
