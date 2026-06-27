package http

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-kit/kit/endpoint"
	"go.uber.org/zap"

	"github.com/flarexio/identity/conf"
)

// scepWebhookRequest is the subset of StepCA's SCEPCHALLENGE webhook body we use.
type scepWebhookRequest struct {
	SCEPChallenge     string `json:"scepChallenge"`
	SCEPTransactionID string `json:"scepTransactionID"`
}

// SCEPVerifyHandler serves StepCA's SCEPCHALLENGE webhook. It authenticates the
// call by HMAC (X-Smallstep-Signature over the raw body), consumes the challenge
// via the endpoint, and answers {"allow": bool}. The webhook id and HMAC secret
// come from conf.G().SCEP; the id, when set, is sanity-checked against the
// X-Smallstep-Webhook-Id header.
func SCEPVerifyHandler(ep endpoint.Endpoint) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg := conf.G().SCEP
		// TEMP (discovery): StepCA presents its own self-generated leaf here.
		// Log it once so we can decide whether to pin its CN later.
		if tls := c.Request.TLS; tls != nil && len(tls.PeerCertificates) > 0 {
			peer := tls.PeerCertificates[0]
			zap.L().Info("scep webhook client cert",
				zap.String("subject", peer.Subject.String()),
				zap.String("issuer", peer.Issuer.String()),
			)
		}

		// Cheap fail-fast first: the id is public and not covered by the HMAC, so
		// it's only a sanity check—but rejecting a misrouted call here avoids
		// reading the body and computing the HMAC below.
		if cfg.WebhookID != "" && c.GetHeader("X-Smallstep-Webhook-Id") != cfg.WebhookID {
			err := errors.New("unexpected webhook id")
			c.String(http.StatusBadRequest, err.Error())
			c.Error(err)
			c.Abort()
			return
		}

		// Raw body is needed for the HMAC, so read it ourselves instead of binding.
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.String(http.StatusBadRequest, err.Error())
			c.Error(err)
			c.Abort()
			return
		}

		// HMAC over the raw body is the real gate.
		if !validSCEPSignature(c.GetHeader("X-Smallstep-Signature"), body, cfg.WebhookSecret) {
			err := errors.New("invalid webhook signature")
			c.String(http.StatusUnauthorized, err.Error())
			c.Error(err)
			c.Abort()
			return
		}

		var req scepWebhookRequest
		if err := json.Unmarshal(body, &req); err != nil {
			c.String(http.StatusBadRequest, err.Error())
			c.Error(err)
			c.Abort()
			return
		}

		// A denied challenge is a normal 200 with allow:false, not an HTTP error.
		subject, err := ep(c.Request.Context(), req.SCEPChallenge)
		if err != nil {
			zap.L().Warn("scep challenge denied",
				zap.String("transaction", req.SCEPTransactionID),
				zap.Error(err),
			)
			c.JSON(http.StatusOK, gin.H{"allow": false})
			return
		}

		zap.L().Info("scep challenge allowed",
			zap.String("transaction", req.SCEPTransactionID),
			zap.Any("subject", subject),
		)
		c.JSON(http.StatusOK, gin.H{"allow": true})
	}
}

// validSCEPSignature constant-time compares StepCA's hex HMAC-SHA256 of the body.
func validSCEPSignature(header string, body, secret []byte) bool {
	if header == "" {
		return false
	}

	sig, err := hex.DecodeString(header)
	if err != nil {
		return false
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write(body)

	return hmac.Equal(sig, mac.Sum(nil))
}
