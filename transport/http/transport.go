package http

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-kit/kit/endpoint"
	"github.com/golang-jwt/jwt/v5"
	"github.com/oklog/ulid/v2"

	"github.com/flarexio/identity"
	"github.com/flarexio/identity/conf"
	"github.com/flarexio/identity/user"
)

func RegisterHandler(endpoint endpoint.Endpoint) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req identity.RegisterRequest
		if err := c.ShouldBind(&req); err != nil {
			c.Abort()
			c.Error(err)
			c.String(http.StatusBadRequest, err.Error())
			return
		}

		resp, err := endpoint(c, req)
		if err != nil {
			c.Abort()
			c.Error(err)
			c.String(http.StatusExpectationFailed, err.Error())
			return
		}

		c.JSON(http.StatusOK, &resp)
	}
}

func OTPVerifyHandler(endpoint endpoint.Endpoint) gin.HandlerFunc {
	return func(c *gin.Context) {
		username := c.Param("user")
		if username == "" {
			err := errors.New("user not found")
			c.Abort()
			c.Error(err)
			c.String(http.StatusBadRequest, err.Error())
			return
		}

		var req identity.OTPVerifyRequest
		if err := c.ShouldBind(&req); err != nil {
			c.Abort()
			c.Error(err)
			c.String(http.StatusBadRequest, err.Error())
			return
		}
		req.Username = username

		resp, err := endpoint(c, req)
		if err != nil {
			c.Abort()
			c.Error(err)
			c.String(http.StatusExpectationFailed, err.Error())
			return
		}

		c.JSON(http.StatusOK, &resp)
	}
}

func SignInHandler(endpoint endpoint.Endpoint) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req identity.SignInRequest
		err := c.ShouldBind(&req)
		if err != nil {
			c.Abort()
			c.Error(err)
			c.String(http.StatusBadRequest, err.Error())
			return
		}

		resp, err := endpoint(c, req)
		if err != nil {
			c.Abort()
			c.Error(err)
			c.String(http.StatusExpectationFailed, err.Error())
			return
		}

		response, ok := resp.(identity.SignInResponse)
		if !ok {
			err := errors.New("invalid user")
			unauthorized(c, http.StatusExpectationFailed, err)
			return
		}

		u := response.User

		cfg := conf.G()
		now := time.Now()
		claims := Claims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    cfg.BaseURL,
				Subject:   u.Username,
				Audience:  cfg.JWT.Audiences,
				ExpiresAt: jwt.NewNumericDate(now.Add(cfg.JWT.Timeout)),
				IssuedAt:  jwt.NewNumericDate(now),
				ID:        ulid.Make().String(),
			},
			Roles: []string{"user"},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
		tokenStr, err := token.SignedString(cfg.JWT.Privkey)
		if err != nil {
			unauthorized(c, http.StatusExpectationFailed, err)
			return
		}

		response.Token = &identity.Token{
			Token:     tokenStr,
			ExpiredAt: now.Add(cfg.JWT.Timeout),
		}

		c.JSON(http.StatusOK, &response)
	}
}

func unauthorized(c *gin.Context, code int, err error) {
	c.Abort()
	c.Error(err)
	c.Header("WWW-Authenticate", "Bearer realm="+issuer)
	c.String(code, err.Error())
}

func RefreshHandler(c *gin.Context) {
	cfg := conf.G()
	if !cfg.JWT.Refresh.Enabled {
		err := errors.New("token refresh disabled")
		c.Abort()
		c.Error(err)
		c.String(http.StatusForbidden, err.Error())
		return
	}

	var claims Claims
	if err := ParseToken(c, &claims); err != nil {
		unauthorized(c, http.StatusUnauthorized, err)
		return
	}

	if time.Since(claims.IssuedAt.Time) > cfg.JWT.Refresh.Maximum {
		err := errors.New("token beyond refresh time")
		unauthorized(c, http.StatusForbidden, err)
		return
	}

	now := time.Now()
	claims.ExpiresAt = jwt.NewNumericDate(now.Add(cfg.JWT.Timeout))
	claims.IssuedAt = jwt.NewNumericDate(now)
	claims.ID = ulid.Make().String()

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tokenStr, err := token.SignedString(cfg.JWT.Privkey)
	if err != nil {
		unauthorized(c, http.StatusExpectationFailed, err)
		return
	}

	t := identity.Token{
		Token:     tokenStr,
		ExpiredAt: now.Add(cfg.JWT.Timeout),
	}

	c.JSON(http.StatusOK, &t)
}

func AddSocialAccountHandler(endpoint endpoint.Endpoint) gin.HandlerFunc {
	return func(c *gin.Context) {
		username := c.Param("user")
		if username == "" {
			err := errors.New("user not found")
			c.Abort()
			c.Error(err)
			c.String(http.StatusBadRequest, err.Error())
			return
		}

		var req identity.AddSocialAccountRequest
		if err := c.ShouldBind(&req); err != nil {
			c.Abort()
			c.Error(err)
			c.String(http.StatusBadRequest, err.Error())
			return
		}
		req.Username = username

		resp, err := endpoint(c, req)
		if err != nil {
			c.Abort()
			c.Error(err)
			c.String(http.StatusExpectationFailed, err.Error())
			return
		}

		c.JSON(http.StatusOK, &resp)
	}
}

func RegisterPasskeyHandler(endpoint endpoint.Endpoint) gin.HandlerFunc {
	return func(c *gin.Context) {
		username := c.Param("user")
		if username == "" {
			err := errors.New("user not found")
			c.Abort()
			c.Error(err)
			c.String(http.StatusBadRequest, err.Error())
			return
		}

		resp, err := endpoint(c, username)
		if err != nil {
			c.Abort()
			c.Error(err)
			c.String(http.StatusExpectationFailed, err.Error())
			return
		}

		c.JSON(http.StatusOK, &resp)
	}
}

func UserHandler(endpoint endpoint.Endpoint) gin.HandlerFunc {
	return func(c *gin.Context) {
		var claims Claims
		if err := ParseToken(c, &claims); err != nil {
			unauthorized(c, http.StatusUnauthorized, err)
			return
		}

		resp, err := endpoint(c, claims.Subject)
		if err != nil {
			c.Abort()
			c.Error(err)
			c.String(http.StatusExpectationFailed, err.Error())
			return
		}

		c.JSON(http.StatusOK, &resp)
	}
}

func DirectUserBySocialIDHandler(endpoint endpoint.Endpoint) gin.HandlerFunc {
	return func(c *gin.Context) {
		subject := c.Param("subject")
		if subject == "" {
			err := errors.New("subject not found")
			c.Abort()
			c.Error(err)
			c.String(http.StatusBadRequest, err.Error())
			return
		}

		socialID := user.SocialID(subject)

		resp, err := endpoint(c, socialID)
		if err != nil {
			c.Abort()
			c.Error(err)
			c.String(http.StatusExpectationFailed, err.Error())
			return
		}

		u, ok := resp.(*user.User)
		if !ok {
			err := errors.New("invalid user response")
			c.Abort()
			c.Error(err)
			c.String(http.StatusExpectationFailed, err.Error())
			return
		}

		cfg := conf.G()
		now := time.Now()

		claims := Claims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    cfg.BaseURL,
				Subject:   u.Username,
				Audience:  cfg.JWT.Audiences,
				ExpiresAt: jwt.NewNumericDate(now.Add(cfg.JWT.Timeout)),
				IssuedAt:  jwt.NewNumericDate(now),
				ID:        ulid.Make().String(),
			},
			Roles: []string{"user"},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
		tokenStr, err := token.SignedString(cfg.JWT.Privkey)
		if err != nil {
			c.Abort()
			c.Error(err)
			c.String(http.StatusExpectationFailed, err.Error())
			return
		}

		response := &identity.SignInResponse{
			User: u,
			Token: &identity.Token{
				Token:     tokenStr,
				ExpiredAt: now.Add(cfg.JWT.Timeout),
			},
		}

		c.JSON(http.StatusOK, &response)
	}
}
