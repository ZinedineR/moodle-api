package api

import (
	"github.com/gin-gonic/gin"
)

func ResponseHeaderFormat() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.RequestURI == "/api/v1/access-token/b2b" {
			c.Writer.Header().Set("x-timestamp", c.GetHeader("X-TIMESTAMP"))
			c.Writer.Header().Set("x-client-key", c.GetHeader("X-CLIENT-KEY"))
			c.Writer.Header().Set("access-control-allow-origin", "*")
			c.Writer.Header().Set("strict-transport-security", "max-age=2592000")
			c.Writer.Header().Set("x-content-type-options", "nosniff")
			c.Writer.Header().Set("x-frame-options", "SAMEORIGIN")
			c.Writer.Header().Set("x-xss-protection", "1; mode=block")
		}
		if c.Request.RequestURI == "/api/v1/utilities/signature-auth" {
			c.Writer.Header().Set("strict-transport-security", "max-age=2592000")
			c.Writer.Header().Set("x-content-type-options", "nosniff")
			c.Writer.Header().Set("x-frame-options", "SAMEORIGIN")
			c.Writer.Header().Set("x-xss-protection", "1; mode=block")
		}

		if c.Request.RequestURI == "/api/v1/utilities/signature-service" {
			c.Writer.Header().Set("access-control-allow-origin", "*")
			c.Writer.Header().Set("strict-transport-security", "max-age=2592000")
			c.Writer.Header().Set("x-content-type-options", "nosniff")
			c.Writer.Header().Set("x-frame-options", "SAMEORIGIN")
			c.Writer.Header().Set("x-xss-protection", "1; mode=block")
		}
	}
}
