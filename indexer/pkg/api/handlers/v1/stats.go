package v1

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type StatsV1Handler struct{}

func NewStatsV1Handler() *StatsV1Handler {
	return &StatsV1Handler{}
}

func (h *StatsV1Handler) Handle(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"stats": map[string]any{
			"totalEntries":          0,
			"storageLocationsCount": 0,
		},
	})
}
