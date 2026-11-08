package security/ssrf

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// ssrfSafeDialContext returns a dial function that validates resolved IPs
// against allowed ranges, preventing SSRF and DNS rebinding attacks.
//
// allowLocal=true: permit loopback/unspecified addresses — only for fixed
// endpoints (e.g. local Ollama/LMStudio on 127.0.0.1). Never true for
// user-controlled URLs.
//
// allowPrivate=true (implies allowLocal): additionally permit RFC1918 —
// only for the fixed-endpoint pool where hostnames are config-decided.
func ssrfSafeDialContext(allowLocal, allowPrivate bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	base := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, fmt.Errorf("ssrf: unsupported network %s", network)
		}
		host, port, err := splitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("ssrf: bad addr %s: %w", addr, err)
		}

		var ips []net.IPAddr
		if ip := net.ParseIP(host); ip != nil {
			ips = []net.IPAddr{{IP: ip}}
		} else {
			resolved, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			ips = resolved
		}

		var chosen net.IP
		for _, ipa := range ips {
			ip := ipa.IP
			blocked := ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
				ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() ||
				ip.IsMulticast() || ip.IsUnspecified()
			allowed := allowLocal && (ip.IsLoopback() || ip.IsUnspecified())
			allowed = allowed || (allowPrivate && ip.IsPrivate())
			if blocked && !allowed {
				auditLog("SSRF_BLOCKED", fmt.Sprintf("host=%s ip=%s denied (not public)", host, ip))
				return nil, fmt.Errorf("ssrf: denied non-public address %s (%s)", host, ip)
			}
			if chosen == nil {
				chosen = ip
			}
		}
		if chosen == nil && !allowLocal && !allowPrivate {
			return nil, fmt.Errorf("ssrf: no resolvable public address for %s", host)
		}
		dialHost := host
		if chosen != nil {
			dialHost = chosen.String() // use verified IP directly → prevents DNS rebinding
		}
		return base.DialContext(ctx, network, joinHostPort(dialHost, port))
	}
}

// ssrfTransportStrict builds a Transport that blocks all private/loopback targets.
func ssrfTransportStrict() *http.Transport {
	return &http.Transport{
		DialContext:         ssrfSafeDialContext(false, false),
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
	}
}

// GuardedClient creates an HTTP client protected against SSRF.
// Auto-redirect is disabled; follow redirects manually via FollowRedirectURL.
func GuardedClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: ssrfTransportStrict(),
	}
}

// RedirectTransport is for the fixed-endpoint pool where loopback/private
// destinations are acceptable (local inference runtimes, cloud providers by config).
func RedirectTransport(allowLocal, allowPrivate bool) *http.Transport {
	return &http.Transport{
		DialContext:       ssrfSafeDialContext(allowLocal, allowPrivate),
		ForceAttemptHTTP2: true,
		MaxIdleConns:      64,
	}
}

// FollowRedirectURL validates a 3xx Location header before following.
// Returns cleaned absolute URL on success; false on rejection.
func FollowRedirectURL(resp *http.Response) (string, bool) {
	if resp == nil {
		return "", false
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		return "", false
	}
	// Parse relative to original URL
	base := resp.Request.URL
	if u, err := base.Parse(loc); err == nil {
		resp.Request.URL = u // update for next hop resolution
	}
	url := resp.Request.URL.String()
	scheme := resp.Request.URL.Scheme
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	if resp.Request.URL.User != nil || resp.Request.URL.Host == "" {
		return "", false
	}
	return url, true
}

// auditLog is a minimal placeholder — will be wired to the real logger.
func auditLog(tag, msg string) {}

// ===== String helpers =====
func splitHostPort(addr string) (host, port string, err error) {
	i := lastIndexOf(addr, ":")
	if i < 0 {
		return addr, "", nil
	}
	h, p := addr[:i], addr[i+1:]
	if h == "" {
		return "", "", fmt.Errorf("empty host")
	}
	return h, p, nil
}
func joinHostPort(h, p string) string { return h + ":" + p }
func lastIndexOf(s, sep string) int {
	i := -1
	for j := 0; j <= len(s)-len(sep); j++ {
		if s[j:j+len(sep)] == sep {
			i = j
		}
	}
	return i
}
