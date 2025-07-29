package line

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-kit/kit/endpoint"
	"github.com/patrickmn/go-cache"
	"golang.org/x/oauth2"

	"github.com/flarexio/identity"
	"github.com/flarexio/identity/conf"
	"github.com/flarexio/identity/user"
)

var (
	config *oauth2.Config
	store  *cache.Cache
)

func SetConfig(provider conf.LineProvider) {
	config = &oauth2.Config{
		ClientID:     provider.Channel.ID,
		ClientSecret: provider.Channel.Secret,
		RedirectURL:  provider.RedirectURI,
		Scopes:       []string{"profile", "openid", "email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://access.line.me/oauth2/v2.1/authorize",
			TokenURL: "https://api.line.me/oauth2/v2.1/token",
		},
	}

	store = cache.New(10*time.Minute, cache.NoExpiration)
}

func generateRandomString(length int) string {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		panic(err.Error())
	}

	return base64.URLEncoding.EncodeToString(bytes)
}

type Session struct {
	State string
	Nonce string
}

func NewSession() Session {
	return Session{
		State: generateRandomString(32),
		Nonce: generateRandomString(32),
	}
}

func LoginAuthURLHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := NewSession()

		store.Set(session.State, session.Nonce, cache.DefaultExpiration)

		authURL := config.AuthCodeURL(session.State,
			oauth2.SetAuthURLParam("response_type", "code"),
			oauth2.SetAuthURLParam("nonce", session.Nonce),
		)

		c.Redirect(http.StatusFound, authURL)
	}
}

func AuthCallback(endpoint endpoint.Endpoint) gin.HandlerFunc {
	return func(c *gin.Context) {
		code := c.Query("code")
		if code == "" {
			err := errors.New("code is required")
			c.String(http.StatusBadRequest, err.Error())
			c.Error(err)
			c.Abort()
			return
		}

		state := c.Query("state")
		if state == "" {
			err := errors.New("state is required")
			c.String(http.StatusBadRequest, err.Error())
			c.Error(err)
			c.Abort()
			return
		}

		nonce, ok := store.Get(state)
		if !ok {
			err := errors.New("invalid state")
			c.String(http.StatusBadRequest, err.Error())
			c.Error(err)
			c.Abort()
			return
		}
		defer store.Delete(state)

		ctx := c.Request.Context()
		ctx = context.WithValue(ctx, user.Nonce, nonce)

		token, err := config.Exchange(ctx, code)
		if err != nil {
			c.String(http.StatusInternalServerError, err.Error())
			c.Error(err)
			c.Abort()
			return
		}

		idToken, ok := token.Extra("id_token").(string)
		if !ok {
			err := errors.New("id_token not found in token response")
			c.String(http.StatusInternalServerError, err.Error())
			c.Error(err)
			c.Abort()
			return
		}

		req := identity.SignInRequest{
			Provider:   user.LINE,
			Credential: idToken,
		}

		if _, err := endpoint(ctx, req); err != nil {
			c.String(http.StatusExpectationFailed, err.Error())
			c.Error(err)
			c.Abort()
			return
		}

		c.String(http.StatusOK, "Login successful! You can close this window now.")
	}
}
