package health

import "github.com/gin-gonic/gin"

type Status struct{}

func NewHealthStatus() *Status {
	return &Status{}
}

func (h *Status) HandleLiveness(c *gin.Context) {
}

func (h *Status) HandleReadiness(c *gin.Context) {
}
