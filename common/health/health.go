package health

import (
	"net/http"
)

// HealthReporter should be implemented by any type requiring health checks.
type HealthReporter interface {
	// Ready should return nil if ready, or an error message otherwise. From the k8s docs:
	// > ready means it's initialized and healthy means that it can accept traffic in kubernetes
	// See: https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/
	Ready() error
	// HealthReport returns a full health report of the callee including its dependencies.
	// Keys are based on Name(), with nil values when healthy or errors otherwise.
	// Use CopyHealth to collect reports from sub-services.
	// This should run very fast, so avoid doing computation and instead prefer reporting pre-calculated state.
	HealthReport() map[string]error
	// Name returns the fully qualified name of the component. Usually the logger name.
	Name() string
}

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

func CheckServiceHealth(
	reporter HealthReporter,
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
