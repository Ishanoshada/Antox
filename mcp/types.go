// Package mcp is a minimal Model Context Protocol (MCP) client for the
// "streamable HTTP" transport. It talks JSON-RPC 2.0 to a single endpoint
// (e.g. the jadx-mcp-server at http://127.0.0.1:8651/mcp) and can handle both
// plain JSON responses and Server-Sent Events (SSE) streams.
package mcp

import "encoding/json"

// JSONRPCError is the JSON-RPC 2.0 error object.
type JSONRPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Request is a JSON-RPC request message (has an id, expects a response).
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response is a JSON-RPC response message.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
}

// ServerInfo is the parsed result of the initialize handshake.
type ServerInfo struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ServerCapabilities `json:"capabilities"`
	ServerInfo      map[string]any     `json:"serverInfo"`
	Instructions    string             `json:"instructions,omitempty"`
}

// ServerCapabilities lists protocol features the server implements.
type ServerCapabilities struct {
	Tools *struct{} `json:"tools,omitempty"`
}

// ContentBlock is one item of a tool result's content array.
type ContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// ToolResult is the parsed result of a tools/call request.
type ToolResult struct {
	Content           []ContentBlock  `json:"content"`
	IsError           bool            `json:"isError"`
	StructuredContent json.RawMessage `json:"structuredContent,omitempty"`
}

// ToolDescription is an entry from the tools/list result.
type ToolDescription struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}
