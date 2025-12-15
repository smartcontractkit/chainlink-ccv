package v1

type ErrorResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
}

func makeErrorResponse(err string) ErrorResponse {
	return ErrorResponse{
		Success: false,
		Error:   err,
	}
}
