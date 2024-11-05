package passkeys

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-kit/kit/endpoint"
	"github.com/go-webauthn/webauthn/protocol"
)

func InitializeRegistrationHandler(endpoint endpoint.Endpoint) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req *InitializeRegistrationRequest
		if err := c.ShouldBind(&req); err != nil {
			c.String(http.StatusBadRequest, err.Error())
			c.Error(err)
			c.Abort()
			return
		}

		ctx := c.Request.Context()
		resp, err := endpoint(ctx, req)
		if err != nil {
			c.String(http.StatusExpectationFailed, err.Error())
			c.Error(err)
			c.Abort()
			return
		}

		c.JSON(http.StatusOK, &resp)
	}
}

func FinalizeRegistrationHandler(endpoint endpoint.Endpoint) gin.HandlerFunc {
	return func(c *gin.Context) {
		req, err := protocol.ParseCredentialCreationResponse(c.Request)
		if err != nil {
			c.String(http.StatusBadRequest, err.Error())
			c.Error(err)
			c.Abort()
			return
		}

		ctx := c.Request.Context()
		resp, err := endpoint(ctx, req)
		if err != nil {
			c.String(http.StatusExpectationFailed, err.Error())
			c.Error(err)
			c.Abort()
			return
		}

		c.JSON(http.StatusOK, &resp)
	}
}

func InitializeLoginHandler(endpoint endpoint.Endpoint) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req *InitializeLoginRequest
		if err := c.ShouldBind(&req); err != nil {
			c.String(http.StatusBadRequest, err.Error())
			c.Error(err)
			c.Abort()
			return
		}

		ctx := c.Request.Context()
		resp, err := endpoint(ctx, req)
		if err != nil {
			c.String(http.StatusExpectationFailed, err.Error())
			c.Error(err)
			c.Abort()
			return
		}

		c.JSON(http.StatusOK, &resp)
	}
}

func FinalizeLoginHandler(endpoint endpoint.Endpoint) gin.HandlerFunc {
	return func(c *gin.Context) {
		req, err := protocol.ParseCredentialRequestResponse(c.Request)
		if err != nil {
			c.String(http.StatusBadRequest, err.Error())
			c.Error(err)
			c.Abort()
			return
		}

		ctx := c.Request.Context()
		resp, err := endpoint(ctx, req)
		if err != nil {
			c.String(http.StatusExpectationFailed, err.Error())
			c.Error(err)
			c.Abort()
			return
		}

		c.JSON(http.StatusOK, &resp)
	}
}

func InitializeTransactionHandler(endpoint endpoint.Endpoint) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req *InitializeTransactionRequest
		if err := c.ShouldBind(&req); err != nil {
			c.String(http.StatusBadRequest, err.Error())
			c.Error(err)
			c.Abort()
			return
		}

		ctx := c.Request.Context()
		resp, err := endpoint(ctx, req)
		if err != nil {
			c.String(http.StatusExpectationFailed, err.Error())
			c.Error(err)
			c.Abort()
			return
		}

		c.JSON(http.StatusOK, &resp)
	}
}

func FinalizeTransactionHandler(endpoint endpoint.Endpoint) gin.HandlerFunc {
	return func(c *gin.Context) {
		req, err := protocol.ParseCredentialRequestResponse(c.Request)
		if err != nil {
			c.String(http.StatusBadRequest, err.Error())
			c.Error(err)
			c.Abort()
			return
		}

		ctx := c.Request.Context()
		resp, err := endpoint(ctx, req)
		if err != nil {
			c.String(http.StatusExpectationFailed, err.Error())
			c.Error(err)
			c.Abort()
			return
		}

		c.JSON(http.StatusOK, &resp)
	}
}
