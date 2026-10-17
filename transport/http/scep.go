package http

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"unicode"

	"github.com/gin-gonic/gin"
	"github.com/go-kit/kit/endpoint"
	"go.uber.org/zap"

	"github.com/flarexio/identity/conf"
)

const maxSCEPSubject = 64 // the X.509 upper bound for a CommonName

func validSCEPSubject(s string) bool {
	if s == "" || len(s) > maxSCEPSubject {
		return false
	}

	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}

	return true
}

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
		if err := c.ShouldBindJSON(&req); err != nil {
			badRequest(c, err)
			return
		}

		if !validSCEPSubject(req.Subject) {
			badRequest(c, errors.New("invalid subject"))
			return
		}

		challenge, err := ep(c.Request.Context(), req.Subject)
		if err != nil {
			Fail(c, err)
			return
		}

		c.JSON(http.StatusOK, gin.H{"challenge": challenge})
	}
}

// SCEPVerifyHandler serves StepCA's SCEPCHALLENGE webhook, authenticated by HMAC
// over the raw body, and answers {"allow": bool}.
func SCEPVerifyHandler(ep endpoint.Endpoint, cfg conf.SCEP, log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// The mTLS layer already verified this cert against ClientCAs, so its
		// Subject/Issuer are trustworthy; pin them to StepCA's leaf.
		tls := c.Request.TLS
		if tls == nil || len(tls.PeerCertificates) == 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, ErrorResponse{"client_certificate_required", "client certificate required"})
			return
		}

		if peer := tls.PeerCertificates[0]; cfg.WebhookClientCN != "" && peer.Subject.CommonName != cfg.WebhookClientCN {
			log.Warn("unexpected scep webhook client certificate",
				zap.String("subject", peer.Subject.String()),
				zap.String("issuer", peer.Issuer.String()),
			)
			c.AbortWithStatusJSON(http.StatusUnauthorized, ErrorResponse{"client_certificate_forbidden", "unexpected webhook client certificate"})
			return
		}

		// id is public and unsigned: a cheap fail-fast, not the gate.
		if cfg.WebhookID != "" && c.GetHeader("X-Smallstep-Webhook-Id") != cfg.WebhookID {
			badRequest(c, errors.New("unexpected webhook id"))
			return
		}

		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			badRequest(c, err)
			return
		}

		if !validSCEPSignature(c.GetHeader("X-Smallstep-Signature"), body, cfg.WebhookSecret) {
			c.Error(errors.New("invalid webhook signature"))
			c.AbortWithStatusJSON(http.StatusUnauthorized, ErrorResponse{"invalid_signature", "invalid webhook signature"})
			return
		}

		var req scepWebhookRequest
		if err := json.Unmarshal(body, &req); err != nil {
			badRequest(c, err)
			return
		}

		// A denied challenge is a normal 200 with allow:false, not an HTTP error.
		subject, err := ep(c.Request.Context(), req.SCEPChallenge)
		if err != nil {
			log.Warn("scep challenge denied",
				zap.String("transaction", req.SCEPTransactionID),
				zap.Error(err),
			)
			c.JSON(http.StatusOK, gin.H{"allow": false})
			return
		}

		log.Info("scep challenge allowed",
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
