package control

import "encoding/json"

// Request is a newline-delimited JSON control request.
type Request struct {
	Op   string          `json:"op"`
	ID   string          `json:"id,omitempty"`
	Data json.RawMessage `json:"data,omitempty"`
}

// Response is a newline-delimited JSON control response.
type Response struct {
	OK    bool            `json:"ok"`
	ID    string          `json:"id,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
	Error string          `json:"error,omitempty"`
	Code  string          `json:"code,omitempty"`
}
