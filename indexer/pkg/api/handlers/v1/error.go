package v1

import (
	"fmt"
	"net/http"
)

var internalServerErrorResponse = makeErrorResponse(http.StatusInternalServerError,
	"An unexpected error occurred. Please try again later.")

type ErrorResponse struct {
	Success bool   `json:"success"           doc:"Indicates whether the request was successful or not."`
	Status  int    `json:"status"            doc:"HTTP status code"                                                         example:"400"`
	Message string `json:"message,omitempty" doc:"A human-readable explanation specific to this occurrence of the problem." example:"Invalid chain selector"`
}

// GetStatus implements the interface huma.StatusError.
func (er ErrorResponse) GetStatus() int {
	return er.Status
}

// GetError implements the interface huma.StatusError.
func (er ErrorResponse) GetError() string {
	return er.Message
}

func (er ErrorResponse) Error() string {
	return fmt.Sprintf("%d: %s", er.Status, er.Message)
}

func makeErrorResponse(status int, message string) ErrorResponse {
	return ErrorResponse{
		Success: false,
		Status:  status,
		Message: message,
	}
}
