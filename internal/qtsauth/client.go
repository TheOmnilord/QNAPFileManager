// Package qtsauth validates a QTS desktop session from inside a QPKG.
//
// The QTS web desktop sets the cookies NAS_USER (the user name) plus either
// qtoken (QTS 5) or NAS_SID (older firmware). A same-origin QPKG receives them
// and validates them against the QTS web server's own CGI endpoint
// /cgi-bin/authLogin.cgi. See docs/research/qts-integration-facts.md §1 and
// docs/design/identity-and-hero-plan.md §1.1, §1.3 and §5.3.
//
// Two rules shape this package:
//
//   - The endpoint is ALWAYS loopback (127.0.0.1) on the port read from
//     /etc/config/uLinux.conf, never a host derived from the incoming request.
//     Trusting the request's Host header would let a caller point validation at
//     a server it controls.
//   - The sid form of the call validates only the token, not the (user, token)
//     pair, so the user name must come from the response body. Otherwise any
//     authenticated user could set NAS_USER=admin in their own browser and be
//     handed an administrator session. Verifier fails closed on that
//     (ErrSIDUnbound) unless AllowSIDWithoutUsername is explicitly set.
//
// This package is stdlib only and depends on no other internal package: the web
// layer glues in identity resolution (internal/idmap).
package qtsauth

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Defaults for a Client talking to the QTS web server on loopback.
const (
	// DefaultPort is the QTS HTTP port when uLinux.conf cannot be read.
	DefaultPort = 8080
	// DefaultSSLPort is the QTS HTTPS (stunnel) port when uLinux.conf cannot be
	// read. QTS "Force HTTPS" redirects the HTTP port here, and on such a unit
	// the loopback validation call must be made over HTTPS instead.
	DefaultSSLPort = 443
	// DefaultTimeout bounds a single authLogin.cgi call. The endpoint is a
	// fork-per-request CGI, so it must never be allowed to hang a handler.
	DefaultTimeout = 5 * time.Second
	// DefaultMaxBody caps the response body we are willing to read.
	DefaultMaxBody int64 = 64 << 10
	// AuthPath is the QTS validation endpoint, relative to the web root.
	AuthPath = "/cgi-bin/authLogin.cgi"
)

// EncodePassword encodes a plaintext password for the pwd= parameter of the
// credential-proxy login call.
//
// VERIFY ON NAS: QNAP's own web UI passes pwd through a JavaScript function
// named ezEncode. It is *believed* to be plain standard base64 of the UTF-8
// password (that is what public QNAP API notes and third-party clients use),
// but this has not been confirmed against the firmware in scope. Confirm by
// signing in through the QTS desktop with the browser network tab open and
// comparing the pwd value with base64(password); if it differs, replace this
// variable rather than changing call sites. It is a variable precisely so the
// encoding can be swapped once the real answer is known.
var EncodePassword = func(password string) string {
	return base64.StdEncoding.EncodeToString([]byte(password))
}

// Client calls the QTS authLogin.cgi endpoint.
//
// A Client must not be copied after first use.
type Client struct {
	// BaseURL is the scheme://host:port of the QTS web server, without a
	// trailing slash, e.g. "http://127.0.0.1:8080". Always loopback.
	BaseURL string
	// HTTP is the client used for calls. When nil a default built by
	// NewHTTPClient is used: 5 s timeout, no redirect following, and
	// InsecureSkipVerify only when BaseURL is https (QTS "Force HTTPS" uses a
	// self-signed certificate with no usable CN/SAN).
	HTTP *http.Client
	// MaxBody caps the response body read from the endpoint. Zero means
	// DefaultMaxBody.
	MaxBody int64
	// SSLPort is the QTS HTTPS (stunnel) port used for the loopback fallback
	// when BaseURL is http and the unit enforces HTTPS. Zero means
	// DefaultSSLPort. It is only ever combined with host 127.0.0.1.
	SSLPort int

	once sync.Once
	def  *http.Client
}

// New returns a Client for the given base URL with the default HTTP client.
func New(baseURL string) *Client {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	return &Client{
		BaseURL: baseURL,
		HTTP:    NewHTTPClient(baseURL, DefaultTimeout),
		MaxBody: DefaultMaxBody,
	}
}

// NewHTTPClient builds the HTTP client this package expects: a fixed timeout,
// redirects never followed, and TLS verification disabled only when baseURL is
// https (loopback to a self-signed QTS certificate).
func NewHTTPClient(baseURL string, timeout time.Duration) *http.Client {
	tr := &http.Transport{
		DisableKeepAlives: true,
		Proxy:             nil, // never route a loopback call through a proxy
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(baseURL)), "https://") {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // QTS ships a self-signed certificate with no usable CN/SAN; the endpoint is loopback only.
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Detect builds a Client for the local QTS web server, reading the HTTP port
// from uLinux.conf. The host is always loopback; only the port is taken from
// configuration. Any failure (missing file, unreadable, no usable key) falls
// back to DefaultPort, so Detect never returns nil.
//
// VERIFY ON NAS: the exact [System] key names for the web port. PLAN.md item 6
// and identity-and-hero-plan.md §5.4 item 8 both list this as unverified; the
// keys tried here are the ones QNAP firmware is reported to use.
func Detect(ulinuxConfPath string) *Client {
	c := New("http://127.0.0.1:" + strconv.Itoa(DetectPort(ulinuxConfPath)))
	c.SSLPort = DetectSSLPort(ulinuxConfPath)
	return c
}

// DetectSSLPort returns the QTS HTTPS (stunnel) port from uLinux.conf, or
// DefaultSSLPort. It is the port the loopback fallback uses when the unit
// enforces HTTPS (Force HTTPS) and the plain HTTP port only redirects.
func DetectSSLPort(ulinuxConfPath string) int {
	if sec, err := readINISection(ulinuxConfPath, "Stunnel"); err == nil {
		for _, key := range []string{"port", "ssl port"} {
			if v, ok := sec[key]; ok {
				if p, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && p > 0 && p < 65536 {
					return p
				}
			}
		}
	}
	return DefaultSSLPort
}

// DetectPort returns the QTS web port from uLinux.conf, or DefaultPort.
func DetectPort(ulinuxConfPath string) int {
	sec, err := readINISection(ulinuxConfPath, "System")
	if err != nil {
		return DefaultPort
	}
	// Ordered: the first key that yields a usable port wins.
	for _, key := range []string{"web access port", "web access port enable"} {
		v, ok := sec[key]
		if !ok {
			continue
		}
		if p, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && p > 0 && p < 65536 {
			return p
		}
	}
	return DefaultPort
}

// readINISection reads one section of a small INI file (uLinux.conf style) and
// returns its keys lower-cased. Comments start with '#' or ';'. Values may be
// wrapped in single or double quotes. Unknown syntax is skipped, not an error:
// this file is written by the firmware and must never be able to panic us.
func readINISection(path, section string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	want := strings.ToLower(section)
	out := map[string]string{}
	in := false
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if end := strings.Index(line, "]"); end > 0 {
				in = strings.EqualFold(strings.TrimSpace(line[1:end]), want)
			}
			continue
		}
		if !in {
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:eq]))
		val := strings.TrimSpace(line[eq+1:])
		if len(val) >= 2 {
			if (val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'') {
				val = val[1 : len(val)-1]
			}
		}
		if key == "" {
			continue
		}
		if _, dup := out[key]; !dup {
			out[key] = val
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	c.once.Do(func() { c.def = NewHTTPClient(c.BaseURL, DefaultTimeout) })
	return c.def
}

func (c *Client) maxBody() int64 {
	if c.MaxBody > 0 {
		return c.MaxBody
	}
	return DefaultMaxBody
}

// ValidateQToken validates the (user, qtoken) pair, the QTS 5 form. Because the
// pair is validated together, binding the resulting session to the NAS_USER
// cookie is safe.
func (c *Client) ValidateQToken(ctx context.Context, user, qtoken string) (Result, error) {
	q := "qtoken=" + url.QueryEscape(qtoken) + "&user=" + url.QueryEscape(user)
	return c.get(ctx, q)
}

// ValidateSID validates a NAS_SID, the older form. It validates only the token,
// so the caller MUST take the user name from the response (Result.Username) and
// never from the NAS_USER cookie. See Verifier and identity-and-hero-plan.md
// §1.3.
func (c *Client) ValidateSID(ctx context.Context, sid string) (Result, error) {
	return c.get(ctx, "sid="+url.QueryEscape(sid))
}

// Login performs the credential-proxy call with an explicit user name and
// password, the fallback door when QTS cookies do not reach us. The password is
// passed through EncodePassword (see the VERIFY ON NAS note there).
func (c *Client) Login(ctx context.Context, user, password string) (Result, error) {
	q := "user=" + url.QueryEscape(user) + "&pwd=" + url.QueryEscape(EncodePassword(password))
	return c.get(ctx, q)
}

func (c *Client) get(ctx context.Context, query string) (Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		return Result{}, fmt.Errorf("qtsauth: empty BaseURL: %w", ErrUnreachable)
	}
	res, fallback, err := c.getFrom(ctx, base, query)
	if err == nil || fallback == "" {
		return res, err
	}
	// The unit enforces HTTPS: the plain HTTP port only redirects here, or is
	// closed. Retry once over HTTPS on loopback, with the self-signed QTS
	// certificate accepted. There is no second fallback, so this cannot loop.
	res, _, err = c.getFrom(ctx, fallback, query)
	return res, err
}

// getFrom performs one validation call against base. A non-empty fallback URL
// means the caller may retry there: it is returned only for an HTTP base that
// redirected to HTTPS (Force HTTPS) or that could not be reached, and it is
// always an https://127.0.0.1 URL, so a retry can never leave the loopback.
func (c *Client) getFrom(ctx context.Context, base, query string) (Result, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+AuthPath+"?"+query, nil)
	if err != nil {
		return Result{}, "", fmt.Errorf("qtsauth: build request for %s: %w", redactQuery(query), ErrUnreachable)
	}
	req.Header.Set("Accept", "text/xml, application/xml, */*")
	req.Header.Set("User-Agent", "qnapfilemanager")

	resp, err := c.clientFor(base).Do(req)
	if err != nil {
		// *url.Error stringifies the whole URL, credential included; keep only
		// the underlying cause so tokens never reach a log.
		var ue *url.Error
		if errors.As(err, &ue) && ue.Err != nil {
			err = ue.Err
		}
		// An unreachable HTTP port may just mean the unit disabled it in favour
		// of HTTPS; offer the configured SSL port on loopback as a fallback.
		return Result{}, c.httpsFallback(base, 0), fmt.Errorf("qtsauth: %s: %w", redactQuery(query), errors.Join(err, ErrUnreachable))
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
	}()

	// Redirects are never followed by the client (CheckRedirect returns
	// ErrUseLastResponse), so a 3xx lands here. A redirect to HTTPS is QTS
	// "Force HTTPS": take only the port from it, force the host back to
	// loopback, and let the caller retry there.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if fb := c.httpsFallback(base, httpsPort(resp.Header.Get("Location"))); fb != "" {
			return Result{}, fb, fmt.Errorf("qtsauth: HTTP endpoint redirected to HTTPS: %w", ErrBadResponse)
		}
		return Result{}, "", fmt.Errorf("qtsauth: unexpected status %d: %w", resp.StatusCode, ErrBadResponse)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return Result{}, "", fmt.Errorf("qtsauth: unexpected status %d: %w", resp.StatusCode, ErrBadResponse)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody()))
	if err != nil {
		return Result{}, "", fmt.Errorf("qtsauth: read body: %w", errors.Join(err, ErrUnreachable))
	}
	res, err := parseResponse(body)
	return res, "", err
}

// clientFor returns the HTTP client to use for base: the configured one when it
// matches BaseURL, otherwise a fresh client whose TLS verification is disabled
// only for the https loopback fallback.
func (c *Client) clientFor(base string) *http.Client {
	if strings.EqualFold(strings.TrimRight(base, "/"), strings.TrimRight(c.BaseURL, "/")) {
		return c.httpClient()
	}
	timeout := DefaultTimeout
	if c.HTTP != nil && c.HTTP.Timeout > 0 {
		timeout = c.HTTP.Timeout
	}
	return NewHTTPClient(base, timeout)
}

// httpsFallback returns the loopback HTTPS URL to retry against, or "" when no
// fallback applies. It is offered only for an http base (so a retry never
// loops), and it always pins the host to 127.0.0.1: only the numeric port is
// taken from the redirect (port>0) or, failing that, from configuration.
func (c *Client) httpsFallback(base string, port int) string {
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(base)), "http://") {
		return ""
	}
	if port <= 0 || port >= 65536 {
		port = c.SSLPort
	}
	if port <= 0 || port >= 65536 {
		port = DefaultSSLPort
	}
	return "https://127.0.0.1:" + strconv.Itoa(port)
}

// httpsPort returns the port of an https redirect Location, or 0 when the
// Location is missing, unparseable, or not https. Only the port is ever used;
// the host in the Location is discarded so validation stays on loopback.
func httpsPort(location string) int {
	if location == "" {
		return 0
	}
	u, err := url.Parse(location)
	if err != nil || !strings.EqualFold(u.Scheme, "https") {
		return 0
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil && n > 0 && n < 65536 {
			return n
		}
		return 0
	}
	return 443
}

// redactQuery keeps token values out of error strings and logs.
func redactQuery(query string) string {
	var keys []string
	for _, part := range strings.Split(query, "&") {
		if eq := strings.Index(part, "="); eq > 0 {
			keys = append(keys, part[:eq])
		}
	}
	return AuthPath + "?" + strings.Join(keys, "&") + "=<redacted>"
}
