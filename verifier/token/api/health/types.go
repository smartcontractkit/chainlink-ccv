package health

import "github.com/smartcontractkit/chainlink-ccv/protocol"

type ServiceStatus string

const (
	Ready    ServiceStatus = "ready"
	NotReady ServiceStatus = "not_ready"
)

type Response struct {
	Status   ServiceStatus    `json:"status"`
	Services []ServicesHealth `json:"services"`
}

type ServicesHealth struct {
	Name   string           `json:"name"`
	Status ServiceStatus    `json:"status"`
	Error  string           `json:"error,omitempty"`
	Report map[string]error `json:"report,omitempty"`
}

func NewResponse(status ServiceStatus, services []ServicesHealth) Response {
	return Response{
		Status:   status,
		Services: services,
	}
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
