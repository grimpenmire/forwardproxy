package wss_handshake_tunnel

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"net"
	"net/http"
	"strconv"
	"strings"
)

func init() {
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("wss_handshake_tunnel", parseCaddyfile)
}

type Middleware struct {
	logger *zap.Logger
}

type HeaderTranslator struct {
	original http.ResponseWriter
	logger   *zap.Logger
	wsKey    string
}

func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.wss_handshake_tunnel",
		New: func() caddy.Module { return new(Middleware) },
	}
}

func (m Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	m.logger.Info("xx servehttp " + r.Method + " " + r.URL.Host + " " + r.URL.Path)

	if r.Method != http.MethodGet {
		return next.ServeHTTP(w, r)
	}

	if r.Header.Get("Upgrade") != "websocket" {
		return next.ServeHTTP(w, r)
	}

	if strings.ToLower(r.Header.Get("Connection")) != "upgrade" {
		return next.ServeHTTP(w, r)
	}

	var wsKey string
	if val := r.Header.Get("Sec-Websocket-Key"); val == "" {
		return next.ServeHTTP(w, r)
	} else {
		wsKey = val
	}

	var connectHost string
	if val := r.Header.Get("X-Connect-Host"); val == "" {
		return next.ServeHTTP(w, r)
	} else {
		connectHost = val
	}

	r.Method = http.MethodConnect
	r.URL.Host = connectHost
	r.Host = connectHost
	r.Header.Del("Upgrade")
	r.Header.Del("Connection")
	r.Header.Del("Sec-Websocket-Key")
	r.Header.Del("X-Connect-Host")

	// We'll be depending on this in HeaderTranslator.WriteHeader
	_, ok := w.(http.Flusher)
	if !ok {
		return caddyhttp.Error(http.StatusInternalServerError,
			fmt.Errorf("ResponseWriter doesn't implement http.Flusher"))
	}
	_, ok = w.(http.Hijacker)
	if !ok {
		return caddyhttp.Error(http.StatusInternalServerError,
			fmt.Errorf("ResponseWriter does not implement http.Hijacker"))
	}

	translator := HeaderTranslator{w, m.logger, wsKey}

	return next.ServeHTTP(translator, r)
}

func (m *Middleware) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	return nil
}

func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			// too many arguments
			return d.ArgErr()
		}
	}
	return nil
}

func (ht HeaderTranslator) Header() http.Header {
	ht.logger.Info("ht.Header")
	return ht.original.Header()
}

func (ht HeaderTranslator) Write(data []byte) (int, error) {
	ht.logger.Info("ht.Write")
	return ht.original.Write(data)
}

func (ht HeaderTranslator) WriteHeader(statusCode int) {
	ht.logger.Info("ht.WriteHeader " + strconv.Itoa(statusCode))
	if statusCode == http.StatusOK {
		ht.logger.Info("   ht.WriteHeader translating")
		statusCode = http.StatusSwitchingProtocols

		ht.original.Header().Set("Upgrade", "websocket")
		ht.original.Header().Set("Connection", "Upgrade")

		accept := ht.wsKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
		hasher := sha1.New()
		hasher.Write([]byte(accept))
		accept = base64.URLEncoding.EncodeToString(hasher.Sum(nil))
		ht.original.Header().Set("Sec-Websocket-Accept", accept)

		ht.original.Header().Del("padding")
	}
	ht.original.WriteHeader(statusCode)
}

func (ht HeaderTranslator) Flush() {
	ht.logger.Info("ht.Flush")
	// We've already made sure this cast works in ServeHttp
	flusher := ht.original.(http.Flusher)
	flusher.Flush()
}

func (ht HeaderTranslator) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker := ht.original.(http.Hijacker)
	return hijacker.Hijack()
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Middleware
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// interface guards
var (
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
	_ http.ResponseWriter         = (*HeaderTranslator)(nil)
	_ http.Flusher                = (*HeaderTranslator)(nil)
	_ http.Hijacker               = (*HeaderTranslator)(nil)
)
