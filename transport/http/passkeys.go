package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-kit/kit/endpoint"
	"github.com/go-webauthn/webauthn/protocol"

	"github.com/flarexio/identity/passkeys"
)

// The finalize handlers answer with the Passkeys API's token as a bare JSON
// string; the client then presents it to /signin or /users/:user/socials.

func PasskeyFinalizeRegistrationHandler(endpoint endpoint.Endpoint) gin.HandlerFunc {
	return func(c *gin.Context) {
		req, err := protocol.ParseCredentialCreationResponse(c.Request)
		if err != nil {
			badRequest(c, err)
			return
		}

		resp, err := endpoint(c.Request.Context(), req)
		if err != nil {
			Fail(c, err)
			return
		}

		c.JSON(http.StatusOK, resp)
	}
}

func PasskeyInitializeLoginHandler(endpoint endpoint.Endpoint) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Without a user ID the ceremony is for a discoverable credential.
		req := new(passkeys.InitializeLoginRequest)
		if c.Request.ContentLength != 0 {
			if err := c.ShouldBindJSON(req); err != nil {
				badRequest(c, err)
				return
			}
		}

		resp, err := endpoint(c.Request.Context(), req)
		if err != nil {
			Fail(c, err)
			return
		}

		c.JSON(http.StatusOK, resp)
	}
}

func PasskeyFinalizeLoginHandler(endpoint endpoint.Endpoint) gin.HandlerFunc {
	return func(c *gin.Context) {
		req, err := protocol.ParseCredentialRequestResponse(c.Request)
		if err != nil {
			badRequest(c, err)
			return
		}

		resp, err := endpoint(c.Request.Context(), req)
		if err != nil {
			Fail(c, err)
			return
		}

		c.JSON(http.StatusOK, resp)
	}
}
