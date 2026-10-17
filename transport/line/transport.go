// Package line runs the LINE Login (OpenID Connect) authorization code flow
// for signing in and for linking a LINE account to the signed-in user.
package line

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-kit/kit/endpoint"
	"github.com/patrickmn/go-cache"
	"go.uber.org/zap"
	"golang.org/x/oauth2"

	"github.com/flarexio/identity"
	"github.com/flarexio/identity/conf"
	"github.com/flarexio/identity/provider"
	"github.com/flarexio/identity/user"

	transHTTP "github.com/flarexio/identity/transport/http"
)

// stateCookie binds a flow to the browser that started it. Without it,
// anyone could hand a victim a callback URL for a flow they began, and the
// victim's browser would complete it: signing the victim in as the attacker,
// or linking the victim's LINE account to the attacker's user. Lax, because
// the callback is a cross-site navigation from access.line.me.
const stateCookie = "__Host-identity_line_state"

const flowTTL = 10 * time.Minute

type operation int

const (
	signIn operation = iota
	linkAccount
)

type flow struct {
	op       operation
	nonce    string
	verifier string // PKCE
	username string // for linkAccount
}

type Transport struct {
	config   *oauth2.Config
	flows    *cache.Cache // state -> *flow
	signIn   endpoint.Endpoint
	link     endpoint.Endpoint
	log      *zap.Logger
	loginURL string // where the browser lands; the frontend's pages
	homeURL  string
}

func New(cfg conf.LineProvider, signIn, link endpoint.Endpoint, log *zap.Logger) *Transport {
	return &Transport{
		config: &oauth2.Config{
			ClientID:     cfg.Channel.ID,
			ClientSecret: cfg.Channel.Secret,
			RedirectURL:  cfg.RedirectURI,
			Scopes:       []string{"profile", "openid", "email"},
			Endpoint: oauth2.Endpoint{
				AuthURL:   "https://access.line.me/oauth2/v2.1/authorize",
				TokenURL:  "https://api.line.me/oauth2/v2.1/token",
				AuthStyle: oauth2.AuthStyleInParams,
			},
		},
		flows:    cache.New(flowTTL, time.Minute),
		signIn:   signIn,
		link:     link,
		log:      log.With(zap.String("transport", "line")),
		loginURL: "/login",
		homeURL:  "/account",
	}
}

func random() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}

	return base64.RawURLEncoding.EncodeToString(b)
}

// start records a flow, binds it to this browser and returns the URL to
// send the user to.
func (t *Transport) start(c *gin.Context, f *flow) string {
	state := random()
	f.nonce = random()
	f.verifier = oauth2.GenerateVerifier()

	t.flows.Set(state, f, cache.DefaultExpiration)

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     stateCookie,
		Value:    state,
		Path:     "/",
		MaxAge:   int(flowTTL.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	return t.config.AuthCodeURL(state,
		oauth2.SetAuthURLParam("nonce", f.nonce),
		oauth2.S256ChallengeOption(f.verifier),
	)
}

// SignInHandler serves GET /auth/line: a top-level navigation that ends,
// via the callback, with the browser holding a session cookie.
func (t *Transport) SignInHandler(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusFound, t.start(c, &flow{op: signIn}))
}

// LinkHandler serves GET /auth/line/link/:user (behind authorization) and
// answers with the URL to navigate to, as text.
func (t *Transport) LinkHandler(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.String(http.StatusOK, t.start(c, &flow{op: linkAccount, username: c.Param("user")}))
}

// CallbackHandler serves GET /auth/line/callback.
func (t *Transport) CallbackHandler(c *gin.Context) {
	c.Header("Cache-Control", "no-store")

	f, err := t.finish(c)
	if err != nil {
		t.log.Warn("line callback rejected", zap.Error(err))
		t.redirect(c, t.loginURL, "error", "line_failed")
		return
	}

	back := t.loginURL
	if f.op == linkAccount {
		back = t.homeURL
	}

	if reason := c.Query("error"); reason != "" {
		t.log.Info("line authorization not granted", zap.String("reason", reason))
		t.redirect(c, back, "error", "line_cancelled")
		return
	}

	code := c.Query("code")
	if code == "" {
		t.redirect(c, back, "error", "line_failed")
		return
	}

	ctx := c.Request.Context()

	tok, err := t.config.Exchange(ctx, code, oauth2.VerifierOption(f.verifier))
	if err != nil {
		t.log.Warn("line code exchange failed", zap.Error(err))
		t.redirect(c, back, "error", "line_failed")
		return
	}

	idToken, ok := tok.Extra("id_token").(string)
	if !ok {
		t.log.Warn("line token response has no id_token")
		t.redirect(c, back, "error", "line_failed")
		return
	}

	ctx = provider.WithNonce(ctx, f.nonce)

	switch f.op {
	case signIn:
		resp, err := t.signIn(ctx, identity.SignInRequest{
			Provider:   user.LINE,
			Credential: idToken,
		})
		if err != nil {
			t.redirect(c, back, "error", transHTTP.ErrorCode(err))
			return
		}

		response, ok := resp.(identity.SignInResponse)
		if !ok {
			t.redirect(c, back, "error", "line_failed")
			return
		}

		transHTTP.SetSession(c, response)
		t.redirect(c, t.homeURL, "signin", "line")

	case linkAccount:
		_, err := t.link(ctx, identity.AddSocialAccountRequest{
			Provider:   user.LINE,
			Credential: idToken,
			Username:   f.username,
		})
		if err != nil {
			t.redirect(c, back, "error", transHTTP.ErrorCode(err))
			return
		}

		t.redirect(c, t.homeURL, "linked", "line")
	}
}

// finish redeems the flow named by the callback's state, once, and only in
// the browser that started it.
func (t *Transport) finish(c *gin.Context) (*flow, error) {
	state := c.Query("state")
	if state == "" {
		return nil, errors.New("no state")
	}

	cookie, err := c.Cookie(stateCookie)

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     stateCookie,
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	if err != nil || subtle.ConstantTimeCompare([]byte(cookie), []byte(state)) != 1 {
		return nil, errors.New("state does not belong to this browser")
	}

	v, ok := t.flows.Get(state)
	if !ok {
		return nil, errors.New("unknown or expired state")
	}
	t.flows.Delete(state)

	return v.(*flow), nil
}

func (t *Transport) redirect(c *gin.Context, page, key, value string) {
	c.Redirect(http.StatusSeeOther, page+"?"+url.Values{key: {value}}.Encode())
}
