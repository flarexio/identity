package http

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-kit/kit/endpoint"

	"github.com/flarexio/identity"
	"github.com/flarexio/identity/token"
	"github.com/flarexio/identity/user"
)

// SessionCookie holds the browser session (see token.IssueSession). The
// __Host- prefix makes the browser insist on Secure, Path=/ and no Domain,
// so no sibling subdomain can set or overwrite it.
const SessionCookie = "__Host-identity_session"

// SetSession stores the session cookie for resp, if it carries one.
func SetSession(c *gin.Context, resp identity.SignInResponse) {
	if resp.Session == nil {
		return
	}

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     SessionCookie,
		Value:    resp.Session.Token,
		Path:     "/",
		Expires:  resp.Session.ExpiredAt,
		MaxAge:   int(time.Until(resp.Session.ExpiredAt).Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func clearSession(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     SessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func SignInHandler(endpoint endpoint.Endpoint) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req identity.SignInRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			badRequest(c, err)
			return
		}

		resp, err := endpoint(c.Request.Context(), req)
		if err != nil {
			Fail(c, err)
			return
		}

		response, ok := resp.(identity.SignInResponse)
		if !ok {
			Fail(c, errors.New("unexpected sign-in response"))
			return
		}

		SetSession(c, response)
		c.JSON(http.StatusOK, response)
	}
}

// SessionTokenHandler trades the session cookie for an access token, so a
// browser keeps its access token in memory only and recovers it on reload.
func SessionTokenHandler(endpoint endpoint.Endpoint) gin.HandlerFunc {
	return func(c *gin.Context) {
		session, err := c.Cookie(SessionCookie)
		if err != nil || session == "" {
			Fail(c, token.ErrRenewExpired)
			return
		}

		resp, err := endpoint(c.Request.Context(), session)
		if err != nil {
			clearSession(c)
			Fail(c, err)
			return
		}

		c.JSON(http.StatusOK, resp)
	}
}

func SignOutHandler(c *gin.Context) {
	clearSession(c)
	c.Status(http.StatusNoContent)
}

func RefreshHandler(endpoint endpoint.Endpoint) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := ClaimsFrom(c)
		if !ok {
			Fail(c, token.ErrInvalidToken)
			return
		}

		resp, err := endpoint(c.Request.Context(), claims)
		if err != nil {
			Fail(c, err)
			return
		}

		c.JSON(http.StatusOK, resp)
	}
}

func AddSocialAccountHandler(endpoint endpoint.Endpoint) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req identity.AddSocialAccountRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			badRequest(c, err)
			return
		}
		req.Username = c.Param("user")

		resp, err := endpoint(c.Request.Context(), req)
		if err != nil {
			Fail(c, err)
			return
		}

		c.JSON(http.StatusOK, resp)
	}
}

func RemoveSocialAccountHandler(endpoint endpoint.Endpoint) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req identity.RemoveSocialAccountRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			badRequest(c, err)
			return
		}
		req.Username = c.Param("user")

		resp, err := endpoint(c.Request.Context(), req)
		if err != nil {
			Fail(c, err)
			return
		}

		c.JSON(http.StatusOK, resp)
	}
}

// UsernameHandler serves endpoints whose request is just the :user param.
func UsernameHandler(endpoint endpoint.Endpoint) gin.HandlerFunc {
	return func(c *gin.Context) {
		resp, err := endpoint(c.Request.Context(), c.Param("user"))
		if err != nil {
			Fail(c, err)
			return
		}

		if resp == nil {
			c.Status(http.StatusNoContent)
			return
		}

		c.JSON(http.StatusOK, resp)
	}
}

// DeleteUserHandler deletes the user and, when they delete themselves, ends
// the browser session along with the account.
func DeleteUserHandler(endpoint endpoint.Endpoint) gin.HandlerFunc {
	return func(c *gin.Context) {
		username := c.Param("user")

		if _, err := endpoint(c.Request.Context(), username); err != nil {
			Fail(c, err)
			return
		}

		if claims, ok := ClaimsFrom(c); ok && claims.Subject == username {
			clearSession(c)
		}

		c.Status(http.StatusNoContent)
	}
}

// DirectUserBySocialIDHandler serves the mTLS route that mints a token for
// a user by social ID. ?provider= names the provider; without it the ID
// must be unambiguous across providers.
func DirectUserBySocialIDHandler(endpoint endpoint.Endpoint) gin.HandlerFunc {
	return func(c *gin.Context) {
		req := identity.UserBySocialIDRequest{
			Provider: user.SocialProvider(c.Query("provider")),
			SocialID: user.SocialID(c.Param("subject")),
		}

		resp, err := endpoint(c.Request.Context(), req)
		if err != nil {
			Fail(c, err)
			return
		}

		c.JSON(http.StatusOK, resp)
	}
}

func JWKHandler(tokens *token.Issuer) gin.HandlerFunc {
	jwks := tokens.JWKS()

	return func(c *gin.Context) {
		c.Header("Cache-Control", "public, max-age=300")
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Cross-Origin-Resource-Policy", "cross-origin")
		c.JSON(http.StatusOK, jwks)
	}
}
