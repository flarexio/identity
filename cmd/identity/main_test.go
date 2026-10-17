package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"

	"github.com/flarexio/core/events"
	"github.com/flarexio/core/policy"
	"github.com/flarexio/core/pubsub"
	"github.com/flarexio/identity"
	"github.com/flarexio/identity/conf"
	"github.com/flarexio/identity/persistence/inmem"
	"github.com/flarexio/identity/provider"
	"github.com/flarexio/identity/token"
	"github.com/flarexio/identity/user"

	transHTTP "github.com/flarexio/identity/transport/http"
	transPubSub "github.com/flarexio/identity/transport/pubsub"
)

// syncBus projects events as they are published, so a test can read what a
// command wrote straight away.
type syncBus struct {
	handler pubsub.MessageHandler
}

func (b *syncBus) Publish(topic string, data []byte) error {
	return b.handler(context.Background(), &pubsub.Message{Topic: topic, Data: data})
}

func (b *syncBus) Subscribe(string, pubsub.MessageHandler) error { return nil }
func (b *syncBus) Close() error                                  { return nil }

// fakeVerifier accepts credentials of the form "<subject>|<email>".
func fakeVerifier() provider.Verifier {
	return provider.VerifierFunc(func(_ context.Context, credential string) (*provider.Identity, error) {
		subject, email, ok := strings.Cut(credential, "|")
		if !ok || subject == "" {
			return nil, provider.ErrInvalidCredential
		}

		return &provider.Identity{Subject: subject, Email: email, Name: subject}, nil
	})
}

type identityTestSuite struct {
	suite.Suite
	users  user.Repository
	tokens *token.Issuer
	server *server
	router *gin.Engine
	webDir string
}

func (s *identityTestSuite) SetupTest() {
	gin.SetMode(gin.TestMode)
	log := zap.NewNop()

	users, err := inmem.NewUserRepository()
	s.Require().NoError(err)

	var projection identity.EventHandler = identity.NewEventHandler(users)
	events.ReplaceGlobals(&syncBus{transPubSub.EventHandler(identity.EventEndpoint(projection), log)})

	providers := map[user.SocialProvider]identity.Provider{
		user.GOOGLE:   {Verifier: fakeVerifier(), OpensAccounts: true},
		user.LINE:     {Verifier: fakeVerifier(), OpensAccounts: true},
		user.PASSKEYS: {Verifier: fakeVerifier()},
	}

	svc := identity.NewService(users, providers, nil)

	_, key, err := ed25519.GenerateKey(nil)
	s.Require().NoError(err)

	tokens, err := token.NewIssuer(token.Config{
		Issuer:      "identity.example.com",
		Audiences:   []string{"identity.example.com"},
		Key:         key,
		Lifetime:    time.Hour,
		RenewWindow: 2 * time.Hour,
	})
	s.Require().NoError(err)

	rbac, err := policy.NewRegoPolicy(context.Background(), "../../permissions.json")
	s.Require().NoError(err)

	s.webDir = s.T().TempDir()
	s.Require().NoError(os.WriteFile(filepath.Join(s.webDir, "index.html"), []byte("<app-root></app-root>"), 0o600))
	s.Require().NoError(os.WriteFile(filepath.Join(s.webDir, "main-ABC.js"), []byte("console.log(1)"), 0o600))

	s.users = users
	s.tokens = tokens
	s.server = &server{
		cfg: &conf.Config{
			MTLS: conf.MTLS{AllowedOUs: []string{"Service"}},
			SCEP: conf.SCEP{WebhookSecret: []byte("0123456789abcdef0123456789abcdef")},
		},
		log:       log,
		endpoints: identity.NewEndpointSet(svc, tokens),
		tokens:    tokens,
		policy:    rbac,
		webDir:    s.webDir,
	}

	s.router, err = s.server.publicRouter()
	s.Require().NoError(err)
}

type request struct {
	method, path string
	body         any
	bearer       string
	cookies      []*http.Cookie
	header       map[string]string
}

func (s *identityTestSuite) do(r request) *httptest.ResponseRecorder {
	var body *strings.Reader
	if r.body != nil {
		bs, err := json.Marshal(r.body)
		s.Require().NoError(err)
		body = strings.NewReader(string(bs))
	} else {
		body = strings.NewReader("")
	}

	req := httptest.NewRequest(r.method, r.path, body)
	req.RemoteAddr = "192.0.2.1:1234"
	if r.body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if r.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+r.bearer)
	}
	for _, c := range r.cookies {
		req.AddCookie(c)
	}
	for k, v := range r.header {
		req.Header.Set(k, v)
	}

	w := httptest.NewRecorder()
	s.router.ServeHTTP(w, req)
	return w
}

func cookie(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

type signedIn struct {
	User  *user.User   `json:"user"`
	Token *token.Token `json:"token"`
}

func (s *identityTestSuite) signIn(p user.SocialProvider, credential string) (signedIn, *httptest.ResponseRecorder) {
	w := s.do(request{method: "PATCH", path: "/identity/v1/signin",
		body: map[string]any{"provider": p, "credential": credential}})

	var resp signedIn
	if w.Code == http.StatusOK {
		s.Require().NoError(json.Unmarshal(w.Body.Bytes(), &resp))
	}
	return resp, w
}

func (s *identityTestSuite) errorCode(w *httptest.ResponseRecorder) string {
	var e transHTTP.ErrorResponse
	s.Require().NoError(json.Unmarshal(w.Body.Bytes(), &e), w.Body.String())
	return e.Error
}

func (s *identityTestSuite) TestSignInOpensAccountAndSession() {
	resp, w := s.signIn(user.GOOGLE, "g-1|alice@example.com")
	s.Require().Equal(http.StatusOK, w.Code, w.Body.String())
	s.Equal("alice", resp.User.Username)
	s.Equal(user.Activated, resp.User.Status)
	s.Equal("no-store", w.Header().Get("Cache-Control"))

	c := cookie(w, transHTTP.SessionCookie)
	s.Require().NotNil(c)
	s.True(c.HttpOnly)
	s.True(c.Secure)
	s.Equal(http.SameSiteStrictMode, c.SameSite)
	s.NotContains(w.Body.String(), c.Value, "the session token must only travel in the cookie")

	stored, err := s.users.FindBySocialID(user.GOOGLE, "g-1")
	s.Require().NoError(err)
	s.Equal(resp.User.ID, stored.ID)

	again, w := s.signIn(user.GOOGLE, "g-1|alice@example.com")
	s.Require().Equal(http.StatusOK, w.Code)
	s.Equal(resp.User.ID, again.User.ID)
}

func (s *identityTestSuite) TestUsernamesAreSanitizedAndUnique() {
	first, _ := s.signIn(user.GOOGLE, "g-1|Bob.Smith+tag@example.com")
	s.Equal("bob.smithtag", first.User.Username)

	second, _ := s.signIn(user.LINE, "l-1|bob.smithtag@example.org")
	s.True(strings.HasPrefix(second.User.Username, "bob.smithtag."), second.User.Username)

	noEmail, _ := s.signIn(user.LINE, "l-2|")
	s.True(strings.HasPrefix(noEmail.User.Username, "user."), noEmail.User.Username)
}

func (s *identityTestSuite) TestSignInFailuresDoNotLeakDetails() {
	_, w := s.signIn(user.GOOGLE, "garbage")
	s.Equal(http.StatusUnauthorized, w.Code)
	s.Equal("invalid_credential", s.errorCode(w))

	_, w = s.signIn("facebook", "f-1|x@example.com")
	s.Equal(http.StatusBadRequest, w.Code)

	// A passkey alone never opens an account.
	_, w = s.signIn(user.PASSKEYS, "pk-1|")
	s.Equal(http.StatusUnauthorized, w.Code)
	s.Equal("not_registered", s.errorCode(w))
}

func (s *identityTestSuite) TestSignInRejectsCrossSiteAndForms() {
	w := s.do(request{method: "PATCH", path: "/identity/v1/signin",
		body:   map[string]any{"provider": "google", "credential": "g-1|a@example.com"},
		header: map[string]string{"Sec-Fetch-Site": "cross-site"}})
	s.Equal(http.StatusForbidden, w.Code)

	req := httptest.NewRequest("PATCH", "/identity/v1/signin",
		strings.NewReader(url.Values{"provider": {"google"}, "credential": {"g-1|a@example.com"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)
	s.Equal(http.StatusBadRequest, rec.Code, "only JSON, which needs a CORS preflight cross-origin")
}

func (s *identityTestSuite) TestOwnerOnly() {
	alice, _ := s.signIn(user.GOOGLE, "g-1|alice@example.com")
	s.signIn(user.GOOGLE, "g-2|bob@example.com")

	w := s.do(request{method: "GET", path: "/identity/v1/users/alice", bearer: alice.Token.Token})
	s.Equal(http.StatusOK, w.Code)

	w = s.do(request{method: "GET", path: "/identity/v1/users/bob", bearer: alice.Token.Token})
	s.Equal(http.StatusForbidden, w.Code)

	w = s.do(request{method: "GET", path: "/identity/v1/users/alice"})
	s.Equal(http.StatusUnauthorized, w.Code)
}

func (s *identityTestSuite) TestSessionCookieYieldsAccessToken() {
	alice, w := s.signIn(user.GOOGLE, "g-1|alice@example.com")
	session := cookie(w, transHTTP.SessionCookie)

	w = s.do(request{method: "POST", path: "/identity/v1/session/token", cookies: []*http.Cookie{session}})
	s.Require().Equal(http.StatusOK, w.Code, w.Body.String())

	var resp signedIn
	s.Require().NoError(json.Unmarshal(w.Body.Bytes(), &resp))
	s.Equal(alice.User.ID, resp.User.ID)

	claims, err := s.tokens.Parse(resp.Token.Token)
	s.Require().NoError(err)
	s.Equal("alice", claims.Subject)

	w = s.do(request{method: "POST", path: "/identity/v1/session/token", cookies: []*http.Cookie{session},
		header: map[string]string{"Sec-Fetch-Site": "same-site"}})
	s.Equal(http.StatusForbidden, w.Code)

	w = s.do(request{method: "POST", path: "/identity/v1/session/token",
		cookies: []*http.Cookie{{Name: transHTTP.SessionCookie, Value: alice.Token.Token}}})
	s.Equal(http.StatusUnauthorized, w.Code, "an access token is not a session")

	w = s.do(request{method: "DELETE", path: "/identity/v1/session", cookies: []*http.Cookie{session}})
	s.Equal(http.StatusNoContent, w.Code)
	s.Equal(-1, cookie(w, transHTTP.SessionCookie).MaxAge)
}

func (s *identityTestSuite) TestRefresh() {
	alice, _ := s.signIn(user.GOOGLE, "g-1|alice@example.com")

	w := s.do(request{method: "PATCH", path: "/identity/v1/token/refresh", bearer: alice.Token.Token})
	s.Require().Equal(http.StatusOK, w.Code, w.Body.String())

	var tok token.Token
	s.Require().NoError(json.Unmarshal(w.Body.Bytes(), &tok))

	before, _ := s.tokens.Parse(alice.Token.Token)
	after, err := s.tokens.Parse(tok.Token)
	s.Require().NoError(err)
	s.Equal(before.AuthTime.Unix(), after.AuthTime.Unix(), "refreshing must not restart the clock")
}

// The old refresh re-signed whatever claims it was given; a token from
// before uid/auth_time has neither and must go through sign-in.
func (s *identityTestSuite) TestRefreshRefusesLegacyTokens() {
	u := user.NewUser("legacy", "Legacy", "")
	tok, err := s.tokens.Issue(u, time.Now())
	s.Require().NoError(err)

	claims, err := s.tokens.Parse(tok.Token)
	s.Require().NoError(err)
	claims.UserID = ""
	claims.AuthTime = nil

	_, err = identity.RefreshEndpoint(nil, s.tokens)(context.Background(), claims)
	s.ErrorIs(err, token.ErrRenewExpired)
}

// Deleting an account frees its username. Whoever takes it next must not be
// reachable with the old owner's token or session.
func (s *identityTestSuite) TestDeletedAccountCannotRenewIntoNamesake() {
	alice, w := s.signIn(user.GOOGLE, "g-1|alice@example.com")
	session := cookie(w, transHTTP.SessionCookie)

	w = s.do(request{method: "DELETE", path: "/identity/v1/users/alice", bearer: alice.Token.Token})
	s.Require().Equal(http.StatusNoContent, w.Code, w.Body.String())

	namesake, _ := s.signIn(user.GOOGLE, "g-9|alice@example.org")
	s.Require().Equal("alice", namesake.User.Username)
	s.NotEqual(alice.User.ID, namesake.User.ID)

	w = s.do(request{method: "PATCH", path: "/identity/v1/token/refresh", bearer: alice.Token.Token})
	s.Equal(http.StatusUnauthorized, w.Code)
	s.Equal("sign_in_required", s.errorCode(w))

	w = s.do(request{method: "POST", path: "/identity/v1/session/token", cookies: []*http.Cookie{session}})
	s.Equal(http.StatusUnauthorized, w.Code)
}

func (s *identityTestSuite) TestLinkAndUnlink() {
	alice, _ := s.signIn(user.GOOGLE, "g-1|alice@example.com")
	s.signIn(user.LINE, "l-bob|bob@example.com")
	auth := alice.Token.Token

	link := func(p user.SocialProvider, credential string) *httptest.ResponseRecorder {
		return s.do(request{method: "PUT", path: "/identity/v1/users/alice/socials", bearer: auth,
			body: map[string]any{"provider": p, "credential": credential}})
	}

	w := link(user.LINE, "l-alice|")
	s.Require().Equal(http.StatusOK, w.Code, w.Body.String())

	w = link(user.LINE, "l-alice|")
	s.Equal(http.StatusConflict, w.Code)
	s.Equal("already_linked", s.errorCode(w))

	w = link(user.LINE, "l-bob|")
	s.Equal(http.StatusConflict, w.Code)
	s.Equal("linked_elsewhere", s.errorCode(w))

	// Passkeys are registered under the user's own ID.
	w = link(user.PASSKEYS, "someone-else|")
	s.Equal(http.StatusUnauthorized, w.Code)
	w = link(user.PASSKEYS, alice.User.ID.String()+"|")
	s.Equal(http.StatusOK, w.Code, w.Body.String())

	// The passkey now signs in, and its ID rides in the token.
	pk, w := s.signIn(user.PASSKEYS, alice.User.ID.String()+"|")
	s.Require().Equal(http.StatusOK, w.Code)
	claims, err := s.tokens.Parse(pk.Token.Token)
	s.Require().NoError(err)
	s.Equal(alice.User.ID.String(), claims.PasskeyUserID)

	unlink := func(p user.SocialProvider, id string) *httptest.ResponseRecorder {
		return s.do(request{method: "DELETE", path: "/identity/v1/users/alice/socials", bearer: auth,
			body: map[string]any{"provider": p, "social_id": id}})
	}

	s.Equal(http.StatusOK, unlink(user.LINE, "l-alice").Code)
	s.Equal(http.StatusOK, unlink(user.PASSKEYS, alice.User.ID.String()).Code)

	// The unlinked account no longer signs in to alice; it opens its own.
	again, _ := s.signIn(user.LINE, "l-alice|")
	s.NotEqual(alice.User.ID, again.User.ID)

	w = unlink(user.GOOGLE, "g-1")
	s.Equal(http.StatusConflict, w.Code)
	s.Equal("last_account", s.errorCode(w))
}

func (s *identityTestSuite) TestSecurityHeaders() {
	w := s.do(request{method: "GET", path: "/identity/v1/config"})
	s.Equal("nosniff", w.Header().Get("X-Content-Type-Options"))
	s.Equal("DENY", w.Header().Get("X-Frame-Options"))
	s.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'none'")

	w = s.do(request{method: "GET", path: "/account"})
	s.Equal(http.StatusOK, w.Code)
	s.Contains(w.Header().Get("Content-Security-Policy"), "script-src 'self' https://accounts.google.com/gsi/client")
	s.NotContains(w.Header().Get("Content-Security-Policy"), "script-src 'self' 'unsafe-inline'")
}

func (s *identityTestSuite) TestFrontend() {
	w := s.do(request{method: "GET", path: "/account/settings"})
	s.Equal(http.StatusOK, w.Code)
	s.Equal("<app-root></app-root>", w.Body.String())
	s.Equal("no-cache", w.Header().Get("Cache-Control"))

	w = s.do(request{method: "GET", path: "/main-ABC.js"})
	s.Equal(http.StatusOK, w.Code)
	s.Contains(w.Header().Get("Cache-Control"), "immutable")

	w = s.do(request{method: "GET", path: "/missing.js"})
	s.Equal(http.StatusNotFound, w.Code)

	outside := filepath.Join(filepath.Dir(s.webDir), "secret.txt")
	s.Require().NoError(os.WriteFile(outside, []byte("secret"), 0o600))
	defer os.Remove(outside)

	req := httptest.NewRequest("GET", "/x", nil)
	req.URL.Path = "/../secret.txt"
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)
	s.NotContains(rec.Body.String(), "secret")

	w = s.do(request{method: "GET", path: "/identity/v1/nope"})
	s.Equal(http.StatusNotFound, w.Code)
	s.NotContains(w.Body.String(), "app-root", "API paths must not fall back to the app")
}

func (s *identityTestSuite) TestSignInIsRateLimited() {
	var last int
	for range 15 {
		_, w := s.signIn(user.GOOGLE, "garbage")
		last = w.Code
	}
	s.Equal(http.StatusTooManyRequests, last)
}

func peer(ou string) *tls.ConnectionState {
	return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{
		Subject: pkix.Name{CommonName: "peer", OrganizationalUnit: []string{ou}},
	}}}
}

func (s *identityTestSuite) TestMTLSRoutesCheckTheCertificate() {
	challenges, err := inmem.NewChallengeStore()
	s.Require().NoError(err)
	defer challenges.Close()

	r, err := s.server.mtlsRouter(challenges)
	s.Require().NoError(err)

	alice, _ := s.signIn(user.GOOGLE, "g-1|alice@example.com")

	call := func(method, path, body string, state *tls.ConnectionState) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.TLS = state
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	w := call("GET", "/users/g-1?provider=google", "", peer("Service"))
	s.Require().Equal(http.StatusOK, w.Code, w.Body.String())
	var resp signedIn
	s.Require().NoError(json.Unmarshal(w.Body.Bytes(), &resp))
	s.Equal(alice.User.ID, resp.User.ID)

	s.Equal(http.StatusOK, call("GET", "/users/g-1", "", peer("Service")).Code)
	s.Equal(http.StatusNotFound, call("GET", "/users/g-1?provider=line", "", peer("Service")).Code)
	s.Equal(http.StatusForbidden, call("GET", "/users/g-1", "", peer("Device")).Code)

	gen := `{"subject":"device-01"}`
	s.Equal(http.StatusForbidden, call("POST", "/scep/challenge/generate", gen, peer("Device")).Code,
		"a device certificate must not mint enrollment challenges")
	s.Equal(http.StatusOK, call("POST", "/scep/challenge/generate", gen, peer("Service")).Code)
	s.Equal(http.StatusBadRequest, call("POST", "/scep/challenge/generate", `{"subject":"a\nb"}`, peer("Service")).Code)
}

func (s *identityTestSuite) TestLINEFlowIsBoundToTheBrowser() {
	s.server.cfg.Providers.LINE = conf.LineProvider{
		Channel:     conf.OAuthAPI{ID: "123", Secret: "secret"},
		RedirectURI: "https://identity.example.com/auth/line/callback",
	}
	router, err := s.server.publicRouter()
	s.Require().NoError(err)
	s.router = router

	start := func() (string, *http.Cookie) {
		w := s.do(request{method: "GET", path: "/auth/line"})
		s.Require().Equal(http.StatusFound, w.Code)

		loc, err := url.Parse(w.Header().Get("Location"))
		s.Require().NoError(err)
		s.Equal("access.line.me", loc.Host)
		s.Equal("S256", loc.Query().Get("code_challenge_method"))
		s.NotEmpty(loc.Query().Get("nonce"))

		c := cookie(w, "__Host-identity_line_state")
		s.Require().NotNil(c)
		s.Equal(http.SameSiteLaxMode, c.SameSite)
		return loc.Query().Get("state"), c
	}

	callback := func(query url.Values, cookies ...*http.Cookie) string {
		w := s.do(request{method: "GET", path: "/auth/line/callback?" + query.Encode(), cookies: cookies})
		s.Require().Equal(http.StatusSeeOther, w.Code)
		return w.Header().Get("Location")
	}

	state, c := start()

	// Another browser presenting the callback URL gets nowhere.
	s.Equal("/login?error=line_failed", callback(url.Values{"state": {state}, "code": {"x"}}))

	// The owner's browser can redeem it, once. (Declining at LINE avoids
	// a token exchange this test cannot make.)
	state, c = start()
	s.Equal("/login?error=line_cancelled", callback(url.Values{"state": {state}, "error": {"access_denied"}}, c))
	s.Equal("/login?error=line_failed", callback(url.Values{"state": {state}, "error": {"access_denied"}}, c))
}

func TestIdentity(t *testing.T) {
	suite.Run(t, new(identityTestSuite))
}
