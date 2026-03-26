package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"
)

// InterceptEvent represents the data structure we send to the Python Agent
type InterceptEvent struct {
	Timestamp int64             `json:"timestamp"`
	Method    string            `json:"method"`
	Path      string            `json:"path"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body"`
	RemoteIP  string            `json:"remote_ip"`
}

func interceptAndSend(req *http.Request) {
	// 1. Production Safety: Don't crash if there's no body
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			log.Printf("Error reading request body: %v", err)
			return
		}
		// 2. CRITICAL: Put the body back so the Proxy can still forward it to the real app
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	// 3. Extract Headers for Security Context (e.g., User-Agent, Auth tokens)
	headers := make(map[string]string)
	for name, values := range req.Header {
		if len(values) > 0 {
			headers[name] = values[0]
		}
	}

	// 4. Build the Event Object
	event := InterceptEvent{
		Timestamp: time.Now().Unix(),
		Method:    req.Method,
		Path:      req.URL.Path,
		Headers:   headers,
		Body:      string(bodyBytes),
		RemoteIP:  req.RemoteAddr,
	}

	// 5. Serialize to JSON
	payload, err := json.Marshal(event)
	if err != nil {
		log.Printf("Failed to marshal event: %v", err)
		return
	}

	// 6. Push to the Unix Socket (The Bridge)
	// We wrap this in an async call inside main, but the socket write itself 
    // should be handled by our dedicated socket client.
	client := GetSocketClient("../shared/ghostcheck.sock")
    client.Push(payload)
}