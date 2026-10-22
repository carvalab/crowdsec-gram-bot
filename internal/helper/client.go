package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Call sends one request to the helper socket and returns its answer.
func Call(ctx context.Context, path string, req Request) (Response, error) {
	if err := req.Validate(); err != nil {
		return Response{}, err
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return Response{}, fmt.Errorf("helper not reachable (is crowdsec-gram-bot-helper.socket running?): %w", err)
	}
	defer conn.Close()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(45 * time.Second)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return Response{}, err
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return Response{}, fmt.Errorf("send to helper: %w", err)
	}
	var resp Response
	if err := json.NewDecoder(io.LimitReader(conn, maxResponseBytes)).Decode(&resp); err != nil {
		return Response{}, fmt.Errorf("read helper answer: %w", err)
	}
	if !resp.OK {
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}
