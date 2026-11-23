package notify

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/afterdarksys/systemapi-security/internal/codes"
)

const topic = "topic-topic-topic-topic"

func goodContact(t *testing.T) Contact {
	t.Helper()
	c, err := Parse(Prefix + Base + topic)
	if err != nil {
		t.Fatal(err)
	}
	if c.SHA256 == "" || strings.Contains(c.SHA256, topic) || c.Kind != "push" || c.Ref != Base+topic {
		t.Fatalf("%+v", c)
	}
	if Fingerprint(c.Normalized) != c.SHA256 {
		t.Fatal("fingerprint")
	}
	return c
}

func TestParseRejects(t *testing.T) {
	goodContact(t)
	bad := []string{
		"user@example.com",
		Prefix + "https://ntfy.sh/short",
		Prefix + "http://ntfy.sh/" + topic,
		Prefix + "https://evil.example/" + topic,
		Prefix + "https://user:pass@ntfy.sh/" + topic,
		Prefix + "https://ntfy.sh:443/" + topic,
		Prefix + Base + topic + "/",
		Prefix + Base + topic + "?x=1",
		Prefix + Base + topic + "#f",
		Prefix + Base + topic + "/extra",
		Prefix + "https://ntfy.sh./" + topic,
		strings.Repeat("a", ContactMax+1),
		"",
	}
	for _, raw := range bad {
		var looked bool
		s := &Sender{Lookup: func(context.Context, string, string) ([]net.IP, error) {
			looked = true
			return nil, errors.New(raw)
		}}
		if _, err := Parse(raw); codes.Code(err) != codes.BadContact || (err != nil && err.Error() != codes.BadContact) {
			t.Fatalf("%q → %v", raw, err)
		}
		if err := s.CheckEgress(context.Background(), Contact{}); codes.Code(err) != codes.BadContact || looked {
			t.Fatalf("lookup on parse failure %q looked=%v err=%v", raw, looked, err)
		}
	}
}

func TestEgressAndSend(t *testing.T) {
	c := goodContact(t)
	blocked := []string{
		"10.0.0.1", "127.0.0.1", "100.64.0.1", "169.254.1.1", "192.0.2.1",
		"198.18.0.1", "198.51.100.1", "203.0.113.1", "240.0.0.1", "0.1.2.3",
		"192.168.1.1", "172.16.0.1", "192.0.0.1", "192.88.99.1", "224.0.0.1",
		"fc00::1", "::1", "2001:db8::1", "2001:db8:ffff::1",
	}
	for _, ip := range blocked {
		ip := ip
		t.Run(ip, func(t *testing.T) {
			posted := false
			s := sender(func() ([]net.IP, error) {
				return []net.IP{net.ParseIP(ip)}, nil
			}, func(*http.Request, []string) (*http.Response, error) {
				posted = true
				return nil, nil
			})
			err := s.Send(context.Background(), c, []byte("hi"))
			if posted || codes.Code(err) != codes.BlockedAddress {
				t.Fatalf("posted=%v err=%v", posted, err)
			}
		})
	}
	t.Run("split", func(t *testing.T) {
		posted := false
		s := sender(func() ([]net.IP, error) {
			return []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("10.0.0.1")}, nil
		}, func(*http.Request, []string) (*http.Response, error) {
			posted = true
			return nil, nil
		})
		if err := s.Send(context.Background(), c, []byte("hi")); posted || codes.Code(err) != codes.BlockedAddress {
			t.Fatal(err)
		}
	})
	t.Run("public", func(t *testing.T) {
		var pins []string
		var ua, title, pri string
		s := sender(func() ([]net.IP, error) {
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		}, func(req *http.Request, got []string) (*http.Response, error) {
			pins = got
			ua = req.Header.Get("User-Agent")
			title = req.Header.Get("Title")
			pri = req.Header.Get("Priority")
			if req.URL.String() != Base+topic {
				t.Fatal(req.URL)
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(topic))}, nil
		})
		var logs []string
		s.Log = func(code string) { logs = append(logs, code) }
		if err := s.Send(context.Background(), c, []byte("hello")); err != nil {
			t.Fatal(err)
		}
		if len(pins) != 1 || pins[0] != "1.1.1.1:443" || strings.Contains(pins[0], "ntfy") {
			t.Fatal(pins)
		}
		if ua != "secsvc" || title != "secsvc" || pri != "high" {
			t.Fatalf("headers %s %s %s", ua, title, pri)
		}
		if strings.Contains(strings.Join(logs, " "), topic) {
			t.Fatal(logs)
		}
	})
	t.Run("status", func(t *testing.T) {
		s := sender(func() ([]net.IP, error) {
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		}, func(*http.Request, []string) (*http.Response, error) {
			return &http.Response{StatusCode: 500, Body: io.NopCloser(strings.NewReader(topic))}, nil
		})
		var logs []string
		s.Log = func(code string) { logs = append(logs, code) }
		err := s.Send(context.Background(), c, []byte("hi"))
		if codes.Code(err) != codes.SendFailed || strings.Contains(strings.Join(logs, " "), topic) {
			t.Fatalf("%v %v", err, logs)
		}
		var se *StatusError
		if !errors.As(err, &se) || se.Unwrap().Error() != codes.SendFailed {
			t.Fatal(err)
		}
	})
	t.Run("lookup-leak", func(t *testing.T) {
		s := sender(func() ([]net.IP, error) {
			return nil, errors.New("no such host " + Base + topic)
		}, nil)
		var logs []string
		s.Log = func(code string) { logs = append(logs, code) }
		err := s.CheckEgress(context.Background(), c)
		if codes.Code(err) != codes.SendFailed || strings.Join(logs, " ") != codes.SendFailed {
			t.Fatalf("%v %v", err, logs)
		}
	})
	t.Run("timeout-leak", func(t *testing.T) {
		s := sender(func() ([]net.IP, error) {
			return nil, &url.Error{Op: "lookup", URL: Base + topic, Err: context.DeadlineExceeded}
		}, nil)
		var logs []string
		s.Log = func(code string) { logs = append(logs, code) }
		err := s.Send(context.Background(), c, []byte("hi"))
		if codes.Code(err) != codes.Timeout || strings.Contains(strings.Join(logs, " "), topic) {
			t.Fatalf("%v %v", err, logs)
		}
	})
	t.Run("oversize", func(t *testing.T) {
		looked := false
		s := sender(func() ([]net.IP, error) {
			looked = true
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		}, nil)
		err := s.Send(context.Background(), c, bytesOf(BodyMax+1))
		if looked || codes.Code(err) != codes.SendFailed {
			t.Fatalf("looked=%v %v", looked, err)
		}
	})
}

func TestTransportPolicy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9")
	u, err := NoProxy(nil)
	if u != nil || err != nil {
		t.Fatalf("proxy %v %v", u, err)
	}
	c := NewClient([]string{"1.1.1.1:443"})
	if c.Timeout != Timeout {
		t.Fatal(c.Timeout)
	}
	if err := c.CheckRedirect(nil, nil); codes.Code(err) == "" {
		t.Fatal("redirect followed")
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok || tr.Proxy == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS13 || tr.TLSClientConfig.InsecureSkipVerify || tr.TLSClientConfig.ServerName != "ntfy.sh" {
		t.Fatalf("transport %+v", tr)
	}
	got, err := tr.Proxy(&http.Request{URL: &url.URL{Scheme: "https", Host: "ntfy.sh"}})
	if got != nil || err != nil {
		t.Fatalf("env proxy %v %v", got, err)
	}
	var dialed string
	_, err = dialPinned(context.Background(), "tcp", PinTargets("tcp", []net.IP{net.ParseIP("1.1.1.1")}), func(_ context.Context, network, addr string) (net.Conn, error) {
		dialed = addr
		return nil, errors.New("stop")
	})
	if dialed != "1.1.1.1:443" || strings.Contains(dialed, "ntfy") {
		t.Fatal(dialed)
	}
	if codes.Code(err) != codes.SendFailed {
		t.Fatal(err)
	}
}

func sender(look func() ([]net.IP, error), post func(*http.Request, []string) (*http.Response, error)) *Sender {
	s := &Sender{Lookup: func(ctx context.Context, network, host string) ([]net.IP, error) {
		if host != lookupHost {
			return nil, errors.New("wrong host")
		}
		return look()
	}}
	if post != nil {
		s.Post = func(ctx context.Context, req *http.Request, pins []string) (*http.Response, error) {
			return post(req, pins)
		}
	}
	return s
}

func bytesOf(n int) []byte { return make([]byte, n) }
