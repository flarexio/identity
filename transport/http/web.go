package http

import (
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

// pageCSP is the policy for the frontend. Google Identity Services is the
// one third party it loads; component styles are injected at runtime, hence
// 'unsafe-inline' for styles (never for scripts).
const pageCSP = "default-src 'self'; " +
	"script-src 'self' https://accounts.google.com/gsi/client; " +
	"style-src 'self' 'unsafe-inline' https://accounts.google.com/gsi/style; " +
	"frame-src https://accounts.google.com/gsi/; " +
	"connect-src 'self' https://accounts.google.com/gsi/; " +
	"img-src 'self' data: https:; " +
	"font-src 'self'; " +
	"object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"

// Frontend serves the built single-page app in dir. Paths without a file
// extension that match no file get index.html, so client-side routes load;
// paths under apiPrefixes never do, so a mistyped API call fails plainly.
func Frontend(dir string, apiPrefixes ...string) gin.HandlerFunc {
	root := http.Dir(dir)
	index := filepath.Join(dir, "index.html")

	return func(c *gin.Context) {
		if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
			c.AbortWithStatusJSON(http.StatusNotFound, ErrorResponse{"not_found", "not found"})
			return
		}

		name := path.Clean("/" + c.Request.URL.Path)

		for _, prefix := range apiPrefixes {
			if name == prefix || strings.HasPrefix(name, prefix+"/") {
				c.AbortWithStatusJSON(http.StatusNotFound, ErrorResponse{"not_found", "not found"})
				return
			}
		}

		h := c.Writer.Header()
		h.Set("Content-Security-Policy", pageCSP)
		// Google's sign-in popup has to be able to message the page back.
		h.Set("Cross-Origin-Opener-Policy", "same-origin-allow-popups")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), "+
			"publickey-credentials-create=(self), publickey-credentials-get=(self)")

		if f, err := root.Open(name); err == nil {
			info, err := f.Stat()
			f.Close()

			if err == nil && !info.IsDir() && name != "/index.html" {
				// The build fingerprints file names, so they never change.
				h.Set("Cache-Control", "public, max-age=31536000, immutable")
				c.File(filepath.Join(dir, filepath.FromSlash(name)))
				return
			}
		}

		if strings.Contains(path.Base(name), ".") {
			c.AbortWithStatusJSON(http.StatusNotFound, ErrorResponse{"not_found", "not found"})
			return
		}

		h.Set("Cache-Control", "no-cache")
		c.File(index)
	}
}

// FrontendDir returns dir if it holds a built frontend.
func FrontendDir(dir string) (string, bool) {
	info, err := os.Stat(filepath.Join(dir, "index.html"))
	if err != nil || info.IsDir() {
		return "", false
	}

	return dir, true
}
