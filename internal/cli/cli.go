// Package cli is the secsvc command line.
//
// Threats: the seed is never written to stdout or stderr. This process does
// not verify a caller's grant; the daemon does. A contact file must be mode
// 0600 and its text is not printed. Stderr is a stable code. The unix client
// uses notify.NoProxy, because a nil Proxy honors HTTPS_PROXY.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"github.com/afterdarksys/systemapi-security/internal/api"
	"github.com/afterdarksys/systemapi-security/internal/audit"
	"github.com/afterdarksys/systemapi-security/internal/codes"
	"github.com/afterdarksys/systemapi-security/internal/grant"
	"github.com/afterdarksys/systemapi-security/internal/notify"
	"github.com/afterdarksys/systemapi-security/internal/paths"
	"golang.org/x/sys/unix"
)

var (
	stdout io.Writer = os.Stdout
	stderr io.Writer = os.Stderr
	now              = time.Now
	entRe            = regexp.MustCompile(`^[a-z][a-z0-9.]{0,63}$`)
)

// Main runs one secsvc command. Exit 0 is success, 2 is usage or local
// configuration, and 1 is an API denial or a failed audit check.
func Main(args []string) int {
	if len(args) == 0 {
		return fail(2, codes.Usage)
	}
	switch args[0] {
	case "keygen":
		return cmdKeygen(args[1:])
	case "grant":
		return cmdGrant(args[1:])
	case "serve":
		return cmdServe(args[1:])
	case "call":
		return cmdCall(args[1:])
	case "audit":
		return cmdAudit(args[1:])
	default:
		return fail(2, codes.Usage)
	}
}

func cmdKeygen(args []string) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("seed-out", "", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *path == "" {
		return fail(2, codes.Usage)
	}
	seed, pub, err := grant.Generate()
	if err != nil {
		return fail(2, codes.Code(err))
	}
	defer wipe(seed)
	if err := grant.WriteSeed(*path, seed); err != nil {
		return fail(2, codes.Code(err))
	}
	return writeOut("%s\n", grant.PubHex(pub))
}

func cmdGrant(args []string) int {
	fs := flag.NewFlagSet("grant", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	seedPath := fs.String("seed", "", "")
	actor := fs.String("actor", "", "")
	host := fs.String("host", "", "")
	purpose := fs.String("purpose", "", "")
	ttl := fs.String("ttl", "", "")
	lease := fs.String("lease", "", "")
	var ents, watch stringList
	fs.Var(&ents, "entitlement", "")
	fs.Var(&watch, "watch", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return fail(2, codes.Usage)
	}
	if *seedPath == "" || *actor == "" || *host == "" || *purpose == "" || *ttl == "" {
		return fail(2, codes.Usage)
	}
	g := grant.Grant{
		V:       grant.Version,
		Actor:   *actor,
		Host:    *host,
		Purpose: *purpose,
		LeaseID: *lease,
	}
	if err := grantShape(&g, *ttl, []string(ents), []string(watch)); err != nil {
		return fail(2, codes.Code(err))
	}
	seed, err := grant.LoadSeed(*seedPath)
	if err != nil {
		return fail(2, codes.Code(err))
	}
	defer wipe(seed)
	if g.LeaseID == "" {
		id, err := grant.NewLeaseID()
		if err != nil {
			return fail(2, codes.Code(err))
		}
		g.LeaseID = id
	}
	doc, err := grant.Sign(seed, g)
	if err != nil {
		return fail(2, codes.Code(err))
	}
	return writeOut("%s\n", doc)
}

func grantShape(g *grant.Grant, ttl string, ents, watch []string) error {
	switch g.Purpose {
	case grant.PurposeRead, grant.PurposeConfig, grant.PurposeOperate:
	default:
		return codes.E(codes.GrantBadShape)
	}
	if !grant.ActorOK(g.Actor) || !grant.HostOK(g.Host) {
		return codes.E(codes.GrantBadShape)
	}
	d, err := time.ParseDuration(ttl)
	if err != nil {
		return codes.E(codes.Usage)
	}
	if d <= 0 || d%time.Second != 0 || d > time.Duration(grant.MaxTTL)*time.Second {
		return codes.E(codes.GrantTTL)
	}
	g.Exp = now().Unix() + int64(d/time.Second)
	if g.LeaseID != "" && !grant.LeaseOK(g.LeaseID) {
		return codes.E(codes.GrantBadShape)
	}
	if len(ents) == 0 {
		ents = grant.Fill(g.Purpose)
	}
	if err := listShape(ents, true, g.Purpose); err != nil {
		return err
	}
	if err := listShape(watch, false, ""); err != nil {
		return err
	}
	g.Entitlements = ents
	g.Watch = watch
	return nil
}

func listShape(ss []string, ents bool, purpose string) error {
	max := grant.MaxWatch
	if ents {
		max = grant.MaxEntitlements
	}
	if len(ss) > max || dups(ss) {
		return codes.E(codes.GrantBadShape)
	}
	star := false
	root := false
	for _, s := range ss {
		if badToken(s) {
			return codes.E(codes.GrantBadShape)
		}
		if s == "*" {
			star = true
			continue
		}
		if ents {
			if !entRe.MatchString(s) {
				return codes.E(codes.GrantBadShape)
			}
			continue
		}
		if paths.IsRoot(s) {
			root = true
			continue
		}
		if !paths.IsAbsClean(s) {
			return codes.E(codes.GrantBadShape)
		}
	}
	if star {
		return codes.E(codes.GrantStar)
	}
	if root {
		return codes.E(codes.GrantRootSlash)
	}
	if ents {
		allow := grant.Ceiling(purpose)
		for _, s := range ss {
			if !contains(allow, s) {
				return codes.E(codes.GrantPurpose)
			}
		}
	}
	return nil
}

func cmdServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", "", "")
	pub := fs.String("pub", "", "")
	host := fs.String("host", "", "")
	socket := fs.String("socket", "", "")
	interval := fs.Duration("interval", api.DefaultInterval, "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return fail(2, codes.Usage)
	}
	if *dir == "" || *pub == "" || *socket == "" {
		return fail(2, codes.Usage)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	err := api.Serve(ctx, api.Options{
		Dir: *dir, PubPath: *pub, Host: *host, Socket: *socket, Interval: *interval,
	})
	if err != nil {
		return fail(2, codes.Code(err))
	}
	return 0
}

func cmdCall(args []string) int {
	if len(args) == 0 {
		return fail(2, codes.Usage)
	}
	verb := args[0]
	fs := flag.NewFlagSet("call", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	socket := fs.String("socket", "", "")
	grantPath := fs.String("grant", "", "")
	file := fs.String("file", "", "")
	contactFile := fs.String("contact-file", "", "")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || *socket == "" || *grantPath == "" {
		return fail(2, codes.Usage)
	}
	method, path, kind, err := callRoute(verb)
	if err != nil {
		return fail(2, codes.Usage)
	}
	if (kind == "contact") != (*contactFile != "") || (kind == "config") != (*file != "") {
		return fail(2, codes.Usage)
	}
	var body []byte
	switch kind {
	case "contact":
		raw, code, n := readContact(*contactFile)
		if n != 0 {
			return fail(n, code)
		}
		body, err = codes.Marshal(struct {
			Contact string `json:"contact"`
		}{raw})
		if err != nil {
			return fail(2, codes.BadContact)
		}
	case "config":
		var code string
		var n int
		body, code, n = readConfig(*file)
		if n != 0 {
			return fail(n, code)
		}
	}
	doc, code, n := readGrant(*grantPath)
	if n != 0 {
		return fail(n, code)
	}
	return doCall(*socket, method, path, doc, body)
}

func callRoute(verb string) (method, path, kind string, err error) {
	switch verb {
	case "modules":
		return http.MethodGet, "/v1/modules", "", nil
	case "report":
		return http.MethodGet, "/v1/report", "", nil
	case "catalog":
		return http.MethodGet, "/v1/catalog", "", nil
	case "status":
		return http.MethodGet, "/v1/status", "", nil
	case "config":
		return http.MethodGet, "/v1/config", "", nil
	case "findings":
		return http.MethodGet, "/v1/findings", "", nil
	case "audit":
		return http.MethodGet, "/v1/audit", "", nil
	case "verify":
		return http.MethodGet, "/v1/audit/verify", "", nil
	case "scan":
		return http.MethodPost, "/v1/scan", "", nil
	case "baseline":
		return http.MethodPost, "/v1/baseline", "", nil
	case "contact":
		return http.MethodPut, "/v1/contact", "contact", nil
	case "config-set":
		return http.MethodPut, "/v1/config", "config", nil
	default:
		return "", "", "", codes.E(codes.Usage)
	}
}

func cmdAudit(args []string) int {
	if len(args) == 0 || args[0] != "verify" {
		return fail(2, codes.Usage)
	}
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", "", "")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || *dir == "" {
		return fail(2, codes.Usage)
	}
	fi, err := os.Lstat(*dir)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return fail(2, codes.BadDir)
	}
	n, err := audit.VerifyFile(filepath.Join(*dir, "audit.jsonl"))
	if err != nil {
		code := codes.Code(err)
		exit := 1
		if code == codes.BadDir {
			exit = 2
		}
		return fail(exit, code)
	}
	b, err := codes.Marshal(struct {
		OK   bool `json:"ok"`
		Rows int  `json:"rows"`
	}{true, n})
	if err != nil {
		return fail(1, codes.Failed)
	}
	return writeOut("%s\n", b)
}

func doCall(socket, method, path, doc string, body []byte) int {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, "http://secsvc"+path, rdr)
	if err != nil {
		return fail(1, codes.Failed)
	}
	req.Header.Set(api.HeaderGrant, doc)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := api.NewClient(socket).Do(req)
	if err != nil {
		return fail(1, codes.Failed)
	}
	const max = 1 << 20
	b, rerr := io.ReadAll(io.LimitReader(resp.Body, max+1))
	cerr := resp.Body.Close()
	if rerr != nil || cerr != nil || len(b) > max {
		return fail(1, codes.Failed)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if len(b) == 0 || b[len(b)-1] != '\n' {
			b = append(b, '\n')
		}
		if _, err := stdout.Write(b); err != nil {
			return fail(1, codes.Failed)
		}
		return 0
	}
	var env struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(b, &env); err != nil || env.Error == "" {
		return fail(1, codes.Failed)
	}
	return fail(1, env.Error)
}

func readGrant(path string) (string, string, int) {
	b, fi, err := readNoFollow(path, grant.MaxDocument+2)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", codes.Usage, 2
		}
		return "", codes.GrantBadShape, 1
	}
	if !fi.Mode().IsRegular() {
		return "", codes.GrantBadShape, 1
	}
	doc, err := grant.NormalizeWire(b)
	if err != nil {
		return "", codes.Code(err), 1
	}
	return doc, "", 0
}

func readContact(path string) (string, string, int) {
	b, fi, err := readNoFollow(path, notify.ContactMax+1)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", codes.Usage, 2
		}
		return "", codes.BadContact, 2
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 || contactBad(b) {
		return "", codes.BadContact, 2
	}
	return string(b), "", 0
}

func readConfig(path string) ([]byte, string, int) {
	b, fi, err := readNoFollow(path, api.BodyMax+1)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, codes.Usage, 2
		}
		return nil, codes.BadPath, 1
	}
	if !fi.Mode().IsRegular() {
		return nil, codes.BadPath, 1
	}
	if len(b) > api.BodyMax {
		return nil, codes.Oversized, 1
	}
	return b, "", 0
}

func readNoFollow(path string, limit int64) ([]byte, os.FileInfo, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	fi, sterr := f.Stat()
	var b []byte
	var rerr error
	if sterr == nil {
		b, rerr = io.ReadAll(io.LimitReader(f, limit))
	}
	cerr := f.Close()
	if sterr != nil {
		return nil, nil, sterr
	}
	if rerr != nil {
		return nil, nil, rerr
	}
	if cerr != nil {
		return nil, nil, cerr
	}
	return b, fi, nil
}

func badToken(s string) bool {
	if s == "" {
		return true
	}
	for _, r := range s {
		if r == 0 || r == '\n' || r == '\r' {
			return true
		}
	}
	return false
}

func contactBad(b []byte) bool {
	if len(b) == 0 || len(b) > notify.ContactMax {
		return true
	}
	for _, c := range b {
		if c == '\n' || c == '\r' || c == 0 {
			return true
		}
	}
	return false
}

func fail(exit int, code string) int {
	if code == "" {
		code = codes.Failed
	}
	fmt.Fprintf(stderr, "%s\n", code)
	return exit
}

func writeOut(format string, args ...any) int {
	if _, err := fmt.Fprintf(stdout, format, args...); err != nil {
		return fail(1, codes.Failed)
	}
	return 0
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func dups(ss []string) bool {
	seen := make(map[string]struct{}, len(ss))
	for _, s := range ss {
		if _, ok := seen[s]; ok {
			return true
		}
		seen[s] = struct{}{}
	}
	return false
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

type stringList []string

func (s *stringList) String() string { return "" }

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}
