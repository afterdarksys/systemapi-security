// Package notify sends pages to ntfy.sh.
//
// Threats: the contact string is a bearer. Only push:ntfy:https://ntfy.sh/<topic>
// is accepted. Email, other hosts, userinfo, an explicit port, a query, a
// fragment, and a trailing slash are bad_contact. DNS answers are pinned and
// refused when any address is loopback, private, link-local, CGNAT, multicast,
// unspecified, documentation, benchmarking, or otherwise non-public — including
// 198.51.100.0/24 and 203.0.113.0/24. There is no allow-private switch.
// http.Transport.Proxy is a function that returns no proxy: a nil Proxy would
// honor HTTPS_PROXY and could observe the topic URL. TLS is 1.3, redirects are
// not followed, and errors returned to logs are stable codes. The topic is not
// logged. Parent-directory symlinks are out of scope for this package.
package notify

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/afterdarksys/systemapi-security/internal/codes"
)

const (
	ContactMax = 512
	Prefix     = "push:ntfy:"
	Base       = "https://ntfy.sh/"
	BodyMax    = 64 << 10
	Timeout    = 5 * time.Second
	lookupHost = "ntfy.sh"
)

var topicRe = regexp.MustCompile(`^[A-Za-z0-9_-]{20,64}$`)

// Contact is a parsed ntfy target. Normalized is the bearer string.
type Contact struct {
	Kind       string
	Ref        string
	Normalized string
	SHA256     string
	Topic      string
}

// Parse accepts only the notices.js contact form. The error is bad_contact
// and does not wrap a url.Error.
func Parse(raw string) (Contact, error) {
	if raw == "" || len(raw) > ContactMax || !strings.HasPrefix(raw, Prefix) {
		return Contact{}, codes.E(codes.BadContact)
	}
	rawURL := strings.TrimPrefix(raw, Prefix)
	u, err := url.Parse(rawURL)
	if err != nil || u == nil {
		return Contact{}, codes.E(codes.BadContact)
	}
	if u.Scheme != "https" || u.Host != lookupHost || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return Contact{}, codes.E(codes.BadContact)
	}
	topic := strings.TrimPrefix(u.EscapedPath(), "/")
	if strings.Contains(topic, "/") || !topicRe.MatchString(topic) {
		return Contact{}, codes.E(codes.BadContact)
	}
	canon := Base + topic
	if rawURL != canon || raw != Prefix+canon {
		return Contact{}, codes.E(codes.BadContact)
	}
	sum := sha256.Sum256([]byte(raw))
	return Contact{
		Kind: "push", Ref: canon, Normalized: raw,
		SHA256: hex.EncodeToString(sum[:]), Topic: topic,
	}, nil
}

// Fingerprint is the SHA-256 hex of the normalized contact.
func Fingerprint(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// Sender posts a page. Lookup and Post are injectable so tests do not use the network.
type Sender struct {
	Lookup func(ctx context.Context, network, host string) ([]net.IP, error)
	Post   func(ctx context.Context, req *http.Request, pins []string) (*http.Response, error)
	Log    func(code string)
}

// CheckEgress resolves ntfy.sh and refuses a blocked answer. It does not POST.
func (s *Sender) CheckEgress(ctx context.Context, c Contact) error {
	if c.Topic == "" || c.Ref == "" {
		return codes.E(codes.BadContact)
	}
	_, err := s.resolve(ctx)
	s.log(err)
	return err
}

// Send posts body to the pinned addresses. A body over 64 KiB is send_failed.
func (s *Sender) Send(ctx context.Context, c Contact, body []byte) error {
	if c.Topic == "" {
		err := codes.E(codes.BadContact)
		s.log(err)
		return err
	}
	if len(body) > BodyMax {
		err := codes.E(codes.SendFailed)
		s.log(err)
		return err
	}
	ips, err := s.resolve(ctx)
	if err != nil {
		s.log(err)
		return err
	}
	pins := PinTargets("tcp", ips)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Ref, strings.NewReader(string(body)))
	if err != nil {
		err = codes.E(codes.SendFailed)
		s.log(err)
		return err
	}
	req.Header.Set("User-Agent", "secsvc")
	req.Header.Set("Title", "secsvc")
	req.Header.Set("Priority", "high")
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	var resp *http.Response
	if s.Post != nil {
		resp, err = s.Post(ctx, req, pins)
	} else {
		resp, err = NewClient(pins).Do(req)
	}
	if err != nil {
		err = classify(err)
		s.log(err)
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err = &StatusError{Status: resp.StatusCode}
		s.log(err)
		return err
	}
	return nil
}

func (s *Sender) resolve(ctx context.Context) ([]net.IP, error) {
	fn := s.Lookup
	if fn == nil {
		fn = func(ctx context.Context, network, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, network, host)
		}
	}
	ips, err := fn(ctx, "ip", lookupHost)
	if err != nil {
		return nil, classify(err)
	}
	if len(ips) == 0 || anyBlocked(ips) {
		return nil, codes.E(codes.BlockedAddress)
	}
	return ips, nil
}

func (s *Sender) log(err error) {
	if err == nil || s.Log == nil {
		return
	}
	s.Log(codes.Code(err))
}

// StatusError is a non-2xx response. Error is the stable code.
type StatusError struct{ Status int }

func (e *StatusError) Error() string { return codes.SendFailed }

func (e *StatusError) Unwrap() error { return codes.E(codes.SendFailed) }

func classify(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return codes.E(codes.Timeout)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return codes.E(codes.Timeout)
	}
	var ce *codes.Error
	if errors.As(err, &ce) {
		return ce
	}
	return codes.E(codes.SendFailed)
}

// NoProxy ignores the environment. A nil Transport.Proxy would not.
func NoProxy(*http.Request) (*url.URL, error) { return nil, nil }

// NewTransport dials only pins. Proxy is NoProxy, never nil.
func NewTransport(pins []string) *http.Transport {
	dialer := &net.Dialer{Timeout: Timeout}
	return &http.Transport{
		Proxy: NoProxy,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialPinned(ctx, network, filterPins(network, pins), dialer.DialContext)
		},
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			ServerName: lookupHost,
		},
	}
}

// NewClient times out at 5s and refuses redirects.
func NewClient(pins []string) *http.Client {
	return &http.Client{
		Timeout:   Timeout,
		Transport: NewTransport(pins),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return codes.E(codes.Failed)
		},
	}
}

// PinTargets returns host:443 for ips allowed on network. Blocked addresses are omitted.
func PinTargets(network string, ips []net.IP) []string {
	var out []string
	for _, ip := range ips {
		if ip == nil || blocked(ip) {
			continue
		}
		v4 := ip.To4()
		switch network {
		case "tcp4":
			if v4 == nil {
				continue
			}
			ip = v4
		case "tcp6":
			if v4 != nil {
				continue
			}
		default:
			if v4 != nil {
				ip = v4
			}
		}
		out = append(out, net.JoinHostPort(ip.String(), "443"))
	}
	return out
}

func filterPins(network string, pins []string) []string {
	var ips []net.IP
	for _, p := range pins {
		host, _, err := net.SplitHostPort(p)
		if err != nil {
			continue
		}
		if ip := net.ParseIP(host); ip != nil {
			ips = append(ips, ip)
		}
	}
	return PinTargets(network, ips)
}

// dialPinned dials the first target. A target containing "ntfy" is refused.
func dialPinned(ctx context.Context, network string, targets []string, dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	if dial == nil || len(targets) == 0 {
		return nil, codes.E(codes.BlockedAddress)
	}
	var first error
	for _, addr := range targets {
		if strings.Contains(strings.ToLower(addr), "ntfy") {
			return nil, codes.E(codes.BlockedAddress)
		}
		c, err := dial(ctx, network, addr)
		if err == nil {
			return c, nil
		}
		if first == nil {
			first = err
		}
	}
	return nil, classify(first)
}

func anyBlocked(ips []net.IP) bool {
	for _, ip := range ips {
		if ip == nil || blocked(ip) {
			return true
		}
	}
	return false
}

func blocked(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 0 {
			return true
		}
		if v4[0] == 100 && v4[1]&0xc0 == 0x40 {
			return true
		}
		if v4[0] == 192 && v4[1] == 0 && v4[2] == 0 {
			return true
		}
		if v4[0] == 192 && v4[1] == 0 && v4[2] == 2 {
			return true
		}
		if v4[0] == 192 && v4[1] == 88 && v4[2] == 99 {
			return true
		}
		if v4[0] == 198 && (v4[1] == 18 || v4[1] == 19) {
			return true
		}
		if v4[0] == 198 && v4[1] == 51 && v4[2] == 100 {
			return true
		}
		if v4[0] == 203 && v4[1] == 0 && v4[2] == 113 {
			return true
		}
		if v4[0] >= 224 {
			return true
		}
		return false
	}
	if len(ip) == net.IPv6len && ip[0]&0xfe == 0xfc {
		return true
	}
	return false
}
