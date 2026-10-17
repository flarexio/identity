package http

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/flarexio/identity"
	"github.com/flarexio/identity/passkeys"
	"github.com/flarexio/identity/scep"
	"github.com/flarexio/identity/token"
	"github.com/flarexio/identity/user"
)

// ErrorResponse is the body of every error. Message is safe to show; the
// underlying error only goes to the log.
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

type apiError struct {
	status  int
	code    string
	message string
}

var errorTable = []struct {
	err error
	apiError
}{
	{identity.ErrInvalidArgument, apiError{http.StatusBadRequest, "invalid_argument", "invalid request"}},
	{identity.ErrProviderNotSupported, apiError{http.StatusBadRequest, "provider_not_supported", "provider not supported"}},
	{identity.ErrInvalidCredential, apiError{http.StatusUnauthorized, "invalid_credential", "the credential could not be verified"}},
	{identity.ErrNotRegistered, apiError{http.StatusUnauthorized, "not_registered", "no account is linked to this credential"}},
	{token.ErrInvalidToken, apiError{http.StatusUnauthorized, "invalid_token", "invalid or expired token"}},
	{token.ErrRenewExpired, apiError{http.StatusUnauthorized, "sign_in_required", "sign in again"}},
	{identity.ErrAccountInactive, apiError{http.StatusForbidden, "account_inactive", "account is not active"}},
	{user.ErrUserNotFound, apiError{http.StatusNotFound, "not_found", "user not found"}},
	{user.ErrSocialAccountNotFound, apiError{http.StatusNotFound, "not_found", "account not linked"}},
	{user.ErrSocialAccountExists, apiError{http.StatusConflict, "already_linked", "account already linked"}},
	{identity.ErrAccountLinked, apiError{http.StatusConflict, "linked_elsewhere", "account already linked to another user"}},
	{user.ErrLastSocialAccount, apiError{http.StatusConflict, "last_account", "cannot remove the last sign-in method"}},
	{user.ErrUsernameTaken, apiError{http.StatusConflict, "username_taken", "username taken"}},
	{passkeys.ErrRejected, apiError{http.StatusBadRequest, "passkey_rejected", "the passkey ceremony failed"}},
	{scep.ErrChallengeInvalid, apiError{http.StatusBadRequest, "challenge_invalid", "challenge invalid"}},
}

func classify(err error) apiError {
	for _, e := range errorTable {
		if errors.Is(err, e.err) {
			return e.apiError
		}
	}

	return apiError{http.StatusInternalServerError, "internal", "internal error"}
}

// Fail aborts with the response matching err.
func Fail(c *gin.Context, err error) {
	e := classify(err)

	if e.status == http.StatusUnauthorized {
		c.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
	}

	c.Error(err)
	c.AbortWithStatusJSON(e.status, ErrorResponse{e.code, e.message})
}

func badRequest(c *gin.Context, err error) {
	c.Error(err)
	c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse{"invalid_argument", "invalid request"})
}

// ErrorCode is the machine-readable code Fail would answer err with.
func ErrorCode(err error) string {
	return classify(err).code
}
