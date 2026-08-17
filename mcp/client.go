package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// ProtocolVersion is the MCP protocol revision this client speaks.
	ProtocolVersion = "2024-11-05"
	jsonRPCVersion  = "2.0"
)

// Client is a minimal MCP client using the streamable HTTP transport.
// All JSON-RPC messages are POSTed to a single endpoint; responses come back
// either as application/json or as an SSE stream. The session id returned by
// the server on initialize is re-sent on every subsequent request.
type Client struct {
	baseURL   string
	http      *http.Client
	sessionID string
	mu        sync.Mutex
	nextID    int
}

// New creates a client for the given MCP endpoint URL
// (e.g. "http://127.0.0.1:8651/mcp").
func New(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		http:    &http.Client{},
		nextID:  1,
	}
}

// SetTimeout sets the per-request HTTP timeout. Default is none (the caller's
// context controls cancellation).
func (c *Client) SetTimeout(d time.Duration) { c.http.Timeout = d }

// BaseURL returns the endpoint this client talks to.
func (c *Client) BaseURL() string { return c.baseURL }

func (c *Client) nextRequestID() json.RawMessage {
	c.mu.Lock()
	defer c.mu.Unlock()
	id := c.nextID
	c.nextID++
	return json.RawMessage(strconv.Itoa(id))
}

// Initialize performs the MCP handshake and sends the required
// "initialized" notification.
func (c *Client) Initialize(ctx context.Context) (*ServerInfo, error) {
	params := map[string]any{
		"protocolVersion": ProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo": map[string]any{
			"name":    "antox",
			"version": "1.0.0",
		},
	}
	resp, err := c.call(ctx, "initialize", params)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("initialize returned no response")
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("initialize error %d: %s", resp.Error.Code, resp.Error.Message)
	}
	var info ServerInfo
	if err := json.Unmarshal(resp.Result, &info); err != nil {
		return nil, fmt.Errorf("parse initialize result: %w", err)
	}
	// Protocol requires a notifications/initialized notification right after
	// initialize. Fire-and-forget: a failure here is not fatal.
	c.Notify(ctx, "notifications/initialized", map[string]any{})
	return &info, nil
}

// Notify sends a JSON-RPC notification. Notifications expect no response; the
// server answers with HTTP 202 and an empty body.
func (c *Client) Notify(ctx context.Context, method string, params map[string]any) {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": jsonRPCVersion,
		"method":  method,
		"params":  params,
	})
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	c.applyHeaders(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

// ListTools returns the tool names advertised by the server.
func (c *Client) ListTools(ctx context.Context) ([]ToolDescription, error) {
	resp, err := c.call(ctx, "tools/list", nil)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("tools/list returned no response")
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("tools/list error %d: %s", resp.Error.Code, resp.Error.Message)
	}
	var out struct {
		Tools []ToolDescription `json:"tools"`
	}
	if err := json.Unmarshal(resp.Result, &out); err != nil {
		return nil, fmt.Errorf("parse tools/list: %w", err)
	}
	return out.Tools, nil
}

// CallTool invokes a tool by name with the given arguments and returns its
// result. An MCP-level error (either JSON-RPC error or a result marked
// isError=true) is returned as a Go error.
func (c *Client) CallTool(ctx context.Context, name string, args map[string]any) (*ToolResult, error) {
	params := map[string]any{"name": name, "arguments": args}
	resp, err := c.call(ctx, "tools/call", params)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("%s returned no response", name)
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("%s error %d: %s", name, resp.Error.Code, resp.Error.Message)
	}
	var tr ToolResult
	if err := json.Unmarshal(resp.Result, &tr); err != nil {
		return nil, fmt.Errorf("parse %s result: %w", name, err)
	}
	if tr.IsError {
		return &tr, fmt.Errorf("%s returned error: %s", name, tr.Text())
	}
	return &tr, nil
}

// Text concatenates the text content blocks of a tool result.
func (tr *ToolResult) Text() string {
	var sb strings.Builder
	for _, b := range tr.Content {
		if b.Type == "text" {
			sb.WriteString(b.Text)
		}
	}
	return sb.String()
}

func (c *Client) call(ctx context.Context, method string, params any) (*Response, error) {
	id := c.nextRequestID()
	pb, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(map[string]json.RawMessage{
		"jsonrpc": json.RawMessage(`"2.0"`),
		"id":      id,
		"method":  json.RawMessage(strconv.Quote(method)),
		"params":  pb,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	c.applyHeaders(req)

	httpResp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", c.baseURL, err)
	}
	defer httpResp.Body.Close()

	if sid := httpResp.Header.Get("Mcp-Session-Id"); sid != "" {
		c.mu.Lock()
		c.sessionID = sid
		c.mu.Unlock()
	}

	// 202/204 are the standard answers to notifications (no body to parse).
	if httpResp.StatusCode == http.StatusAccepted || httpResp.StatusCode == http.StatusNoContent {
		return nil, nil
	}

	ct := httpResp.Header.Get("Content-Type")
	if strings.Contains(ct, "text/event-stream") {
		return c.readSSE(httpResp.Body)
	}

	data, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}
	var resp Response
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse JSON-RPC response (%d bytes): %w", len(data), err)
	}
	return &resp, nil
}

func (c *Client) applyHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("User-Agent", "antox/1.0")
	c.mu.Lock()
	sid := c.sessionID
	c.mu.Unlock()
	if sid != "" {
		req.Header.Set("Mcp-Session-Id", sid)
	}
}

// readSSE parses a Server-Sent Events body and returns the first JSON-RPC
// response frame found. Server notifications (e.g. progress messages) are
// ignored. Reading stops as soon as the response is seen so long-lived streams
// never hang the client.
func (c *Client) readSSE(body io.Reader) (*Response, error) {
	br := bufio.NewReader(body)
	var dataLines []string
	for {
		line, err := br.ReadString('\n')
		if len(line) > 0 {
			line = strings.TrimRight(line, "\r\n")
			if strings.HasPrefix(line, "data:") {
				dataLines = append(dataLines, strings.TrimSpace(line[len("data:"):]))
			} else if line == "" && len(dataLines) > 0 {
				if r, ok := c.parseSSEData(dataLines); ok {
					return r, nil
				}
				dataLines = nil
			}
		}
		if err != nil {
			if err == io.EOF && len(dataLines) > 0 {
				if r, ok := c.parseSSEData(dataLines); ok {
					return r, nil
				}
			}
			if err == io.EOF {
				return nil, fmt.Errorf("SSE stream ended without a response frame")
			}
			return nil, fmt.Errorf("read SSE stream: %w", err)
		}
	}
}

// parseSSEData turns the accumulated "data:" payloads of one SSE event into a
// JSON-RPC response. Returns ok=false for notification frames (no id result).
func (c *Client) parseSSEData(lines []string) (*Response, bool) {
	payload := strings.Join(lines, "\n")
	var msg struct {
		JSONRPC string           `json:"jsonrpc"`
		ID      json.RawMessage  `json:"id"`
		Result  *json.RawMessage `json:"result"`
		Error   *JSONRPCError    `json:"error"`
	}
	if err := json.Unmarshal([]byte(payload), &msg); err != nil {
		return nil, false
	}
	if msg.Result == nil && msg.Error == nil {
		return nil, false // notification, not a response
	}
	resp := &Response{JSONRPC: msg.JSONRPC, ID: msg.ID, Error: msg.Error}
	if msg.Result != nil {
		resp.Result = *msg.Result
	}
	return resp, true
}
