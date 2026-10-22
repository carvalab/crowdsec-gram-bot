package helper

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os/user"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Backend does the CrowdSec work for one request. CSCLI is the real one.
type Backend interface {
	List(ctx context.Context) ([]Ban, error)
	Delete(ctx context.Context, ip string) (int, error)
	Allow(ctx context.Context, ip string) (time.Time, int, error)
}

// CheckPeer reports whether the process on the other end of c runs as
// root or as the bot user. Socket permissions already limit this; the check
// keeps the helper safe if those are ever loosened.
func CheckPeer(c *net.UnixConn) (uint32, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if credErr != nil {
		return 0, credErr
	}
	if cred.Uid == 0 {
		return 0, nil
	}
	u, err := user.Lookup(BotUser)
	if err != nil {
		return cred.Uid, fmt.Errorf("peer uid %d refused: %w", cred.Uid, err)
	}
	if strconv.FormatUint(uint64(cred.Uid), 10) != u.Uid {
		return cred.Uid, fmt.Errorf("peer uid %d refused", cred.Uid)
	}
	return cred.Uid, nil
}

func readRequest(r io.Reader) (Request, error) {
	line, err := bufio.NewReader(io.LimitReader(r, maxRequestBytes)).ReadBytes('\n')
	if err != nil {
		return Request{}, fmt.Errorf("read request: want one JSON line under %d bytes", maxRequestBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	var req Request
	if err := dec.Decode(&req); err != nil {
		return Request{}, fmt.Errorf("decode request: %w", err)
	}
	if dec.More() {
		return Request{}, errors.New("decode request: trailing data")
	}
	return req, req.Validate()
}

// Serve answers exactly one request on rw and logs what it did.
func Serve(ctx context.Context, rw io.ReadWriter, be Backend) error {
	req, err := readRequest(rw)
	resp := Response{OK: err == nil}
	if err == nil {
		resp, err = handle(ctx, be, req)
	}
	if err != nil {
		resp = Response{Error: err.Error()}
		log.Printf("op=%q ip=%q filter=%q result=error err=%q", req.Op, req.IP, req.Filter, err)
	} else {
		log.Printf("op=%q ip=%q filter=%q result=ok total=%d deleted=%d", req.Op, req.IP, req.Filter, resp.Total, resp.Deleted)
	}
	return json.NewEncoder(rw).Encode(resp)
}

func handle(ctx context.Context, be Backend, req Request) (Response, error) {
	switch req.Op {
	case OpList:
		all, err := be.List(ctx)
		if err != nil {
			return Response{}, err
		}
		bans := slices.DeleteFunc(all, func(b Ban) bool { return !strings.HasPrefix(b.IP, req.Filter) })
		slices.SortStableFunc(bans, func(a, b Ban) int { return b.Created.Compare(a.Created) })
		total := len(bans)
		return Response{OK: true, Total: total, Bans: bans[:min(total, maxListed)]}, nil
	case OpUnban:
		n, err := be.Delete(ctx, req.IP)
		if err != nil {
			return Response{}, err
		}
		return Response{OK: true, Deleted: n}, nil
	case OpAllow:
		until, lifted, err := be.Allow(ctx, req.IP)
		if err != nil {
			return Response{}, err
		}
		n, err := be.Delete(ctx, req.IP)
		if err != nil {
			return Response{}, fmt.Errorf("allowlisted %s but unban failed: %w", req.IP, err)
		}
		return Response{OK: true, Deleted: lifted + n, Until: until}, nil
	}
	return Response{}, fmt.Errorf("unknown op %q", req.Op)
}
