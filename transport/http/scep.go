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

type scepGenerateRequest struct {
	Subject string `json:"subject"`
}

type scepWebhookRequest struct {
	SCEPChallenge     string `json:"scepChallenge"`
	SCEPTransactionID string `json:"scepTransactionID"`
}

// SCEPGenerateHandler mints a one-time challenge for the requested subject.
func SCEPGenerateHandler(ep endpoint.Endpoint) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req scepGenerateRequest
		if err := c.ShouldBind(&req); err != nil {
			c.String(http.StatusBadRequest, err.Error())
			c.Error(err)
			c.Abort()
			return
		}

		if req.Subject == "" {
			err := errors.New("subject required")
			c.String(http.StatusBadRequest, err.Error())
			c.Error(err)
			c.Abort()
			return
		}

		challenge, err := ep(c.Request.Context(), req.Subject)
		if err != nil {
			c.String(http.StatusExpectationFailed, err.Error())
			c.Error(err)
			c.Abort()
			return
		}

		c.JSON(http.StatusOK, gin.H{"challenge": challenge})
	}
}

// SCEPVerifyHandler serves StepCA's SCEPCHALLENGE webhook, authenticated by HMAC
// over the raw body, and answers {"allow": bool}.
func SCEPVerifyHandler(ep endpoint.Endpoint) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg := conf.G().SCEP

		// TEMP (discovery): log StepCA's self-generated leaf to decide pinning.
		if tls := c.Request.TLS; tls != nil && len(tls.PeerCertificates) > 0 {
			peer := tls.PeerCertificates[0]
			zap.L().Info("scep webhook client cert",
				zap.String("subject", peer.Subject.String()),
				zap.String("issuer", peer.Issuer.String()),
			)
		}

		// id is public and unsigned: a cheap fail-fast, not the gate.
		if cfg.WebhookID != "" && c.GetHeader("X-Smallstep-Webhook-Id") != cfg.WebhookID {
			err := errors.New("unexpected webhook id")
			c.String(http.StatusBadRequest, err.Error())
			c.Error(err)
			c.Abort()
			return
		}

		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.String(http.StatusBadRequest, err.Error())
			c.Error(err)
			c.Abort()
			return
		}

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
