package main

import (
	"log"
	"net"
	"sync"
)

// SocketClient manages a persistent connection to the Python Agent
type SocketClient struct {
	Path string
	Conn net.Conn
	mu   sync.Mutex // Ensures thread-safety so multiple requests don't collide
}

var (
	instance *SocketClient
	once     sync.Once
)

// GetSocketClient returns a singleton instance of the client
func GetSocketClient(path string) *SocketClient {
	once.Do(func() {
		instance = &SocketClient{Path: path}
		instance.connect()
	})
	return instance
}

func (s *SocketClient) connect() {
	conn, err := net.Dial("unix", s.Path)
	if err != nil {
		log.Printf("⚠️ Agent not reachable on %s. GhostCheck is in 'Blind Mode'.", s.Path)
		return
	}
	s.Conn = conn
}

func (s *SocketClient) Push(payload []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.Conn == nil {
		s.connect() // Try to reconnect if the agent just started
	}

	if s.Conn != nil {
		// We add a newline so the Python side knows where one JSON ends and the next begins
		_, err := s.Conn.Write(append(payload, '\n'))
		if err != nil {
			log.Printf("❌ Failed to push to Agent: %v", err)
			s.Conn.Close()
			s.Conn = nil
		}
	}
}