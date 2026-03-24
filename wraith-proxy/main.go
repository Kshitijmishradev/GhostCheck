package main

import (
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"
)

func main() {
	// 1. Define CLI Flags for Production flexibility
	targetAddr := flag.String("target", "http://localhost:8080", "The target URL to protect")
	proxyPort := flag.String("port", "9000", "The port GhostCheck listens on")
	flag.Parse()

	// 2. Robust URL Parsing with Error Handling
	target, err := url.Parse(*targetAddr)
	if err != nil {
		log.Fatalf("Critical Error: Invalid target URL [%s]: %v", *targetAddr, err)
	}

	// 3. Production Reverse Proxy Configuration
	proxy := httputil.NewSingleHostReverseProxy(target)
	
	// Set timeouts to prevent hung connections (Crucial for Production)
	proxy.Transport = &http.Transport{
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	// 4. The Interceptor Hook (Director)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		// Propagate the original IP to the backend (Standard for Proxies)
		req.Header.Set("X-GhostCheck-Proxy", "true")
		
		// Async Interception
		go interceptAndSend(req)
	}

	// 5. Start the Server with Timeouts
	server := &http.Server{
		Addr:         ":" + *proxyPort,
		Handler:      proxy,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	log.Printf("🛡️ GhostCheck Production Proxy Started")
	log.Printf("Listening on :%s | Protecting: %s", *proxyPort, *targetAddr)
	
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}