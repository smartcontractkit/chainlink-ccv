package health

import (
	"net/http"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type ReadinessStatus string

const (
	Ready    ReadinessStatus = "ready"
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
