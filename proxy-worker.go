package main

import (
	"bufio"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var (
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	listeners = make(map[int]net.Listener)
	mu        sync.Mutex
)

const (
	certPath = "/usr/local/share/proxyfull/cert.pem"
	keyPath  = "/usr/local/share/proxyfull/key.pem"
)

func main() {
	menu()
}

func menu() {
	scanner := bufio.NewScanner(os.Stdin)
	for {
		// Clear screen
		cmd := exec.Command("clear")
		cmd.Stdout = os.Stdout
		cmd.Run()

		fmt.Println("=== Proxy Menu ===")
		fmt.Println("1. Open port (Multi-protocol: HTTP/HTTPS/WS/WSS/SOCKS)")
		fmt.Println("2. Close port")
		fmt.Println("3. List open ports")
		fmt.Println("4. Exit")
		fmt.Print("Choose an option: ")
		if !scanner.Scan() {
			break
		}
		input := strings.TrimSpace(scanner.Text())
		switch input {
		case "1":
			openPort(scanner)
		case "2":
			closePort(scanner)
		case "3":
			listPorts()
		case "4":
			closeAllPorts()
			os.Exit(0)
		default:
			fmt.Println("Invalid option")
		}
		time.Sleep(2 * time.Second) // Pause to see output before clearing
	}
	if err := scanner.Err(); err != nil {
		log.Fatal("Scanner error:", err)
	}
}

func openPort(scanner *bufio.Scanner) {
	fmt.Print("Enter port to listen on: ")
	if !scanner.Scan() {
		return
	}
	portStr := strings.TrimSpace(scanner.Text())
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		fmt.Println("Invalid port")
		return
	}

	mu.Lock()
	if _, exists := listeners[port]; exists {
		mu.Unlock()
		fmt.Println("Port already open")
		return
	}
	mu.Unlock()

	// Check if certificates exist
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		fmt.Printf("Certificates not found at %s. Run installer first.\n", certPath)
		return
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		fmt.Printf("Key not found at %s. Run installer first.\n", keyPath)
		return
	}
	fmt.Println("Using pre-generated certificates.")

	ln, err := net.Listen("tcp", ":"+portStr)
	if err != nil {
		log.Printf("Failed to listen on port %d: %v", port, err)
		return
	}

	mu.Lock()
	listeners[port] = ln
	mu.Unlock()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if err.(net.Error).Temporary() {
					continue
				}
				log.Printf("Accept error: %v", err)
				break
			}
			go handleConnection(conn, port)
		}
	}()

	fmt.Printf("Multi-protocol port %d opened and listening in background\n", port)
}

func handleConnection(conn net.Conn, port int) {
	defer conn.Close()

	// Sniff first 8 bytes to detect protocol
	buf := make([]byte, 8)
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("Failed to read initial bytes: %v", err)
		return
	}

	protocol := detectProtocol(buf[:n])
	log.Printf("Detected protocol: %s from %s, first bytes: %s", protocol, conn.RemoteAddr(), hex.EncodeToString(buf[:n]))

	switch protocol {
	case "SOCKS5":
		handleSOCKS5(conn, buf[:n])
	case "HTTP":
		handleHTTP(conn, port, false)
	case "TLS", "UNKNOWN": // Treat UNKNOWN as TLS/WSS
		handleTLS(conn, port)
	default:
		log.Printf("Unsupported protocol")
	}
}

func detectProtocol(buf []byte) string {
	if len(buf) >= 1 && buf[0] == 0x05 { // SOCKS5 version
		return "SOCKS5"
	}
	if len(buf) >= 3 && buf[0] == 0x16 && buf[1] == 0x03 { // TLS ClientHello
		return "TLS"
	}
	// Check for HTTP methods (GET, POST, CONNECT, etc.)
	httpMethods := []string{"GET ", "POST ", "PUT ", "HEAD ", "CONNECT ", "OPTIONS ", "DELETE ", "TRACE ", "PATCH "}
	for _, method := range httpMethods {
		if strings.HasPrefix(string(buf), method) {
			return "HTTP"
		}
	}
	return "UNKNOWN"
}

func handleSOCKS5(conn net.Conn, initialBuf []byte) {
	// Process initial buffer (SOCKS5 version and auth methods)
	if initialBuf[0] != 0x05 {
		conn.Write([]byte{0x05, 0x01, 0x00})
		return
	}
	// No auth response
	conn.Write([]byte{0x05, 0x00})

	// Read connect request
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 10 || buf[0] != 0x05 || buf[1] != 0x01 {
		log.Printf("Invalid SOCKS5 connect request: %v, bytes read: %d", err, n)
		return
	}
	// Parse addr (simple: assume IPv4)
	ip := net.IP(buf[4:8])
	port := (uint16(buf[8]) << 8) | uint16(buf[9])
	log.Printf("SOCKS5 connect request to %s:%d", ip, port)

	sshConn, err := net.Dial("tcp", "127.0.0.1:22")
	if err != nil {
		log.Printf("Failed to connect to SSH: %v", err)
		return
	}
	defer sshConn.Close()

	// Reply success
	reply := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	conn.Write(reply)

	// Bidirectional forward
	go io.Copy(conn, sshConn)
	io.Copy(sshConn, conn)
}

func handleHTTP(conn net.Conn, port int, isTLS bool) {
	// Create an HTTP server to handle HTTP/WS requests
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("HTTP request: Method=%s, URL=%s, Headers=%v, RemoteAddr=%s", r.Method, r.URL, r.Header, r.RemoteAddr)

		if r.Method == "CONNECT" {
			// Handle SOCKS-like via CONNECT
			fmt.Fprint(w, "HTTP/1.1 200 Connection established\r\n\r\n")
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				log.Println("Hijacking not supported")
				http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
				return
			}
			clientConn, _, err := hijacker.Hijack()
			if err != nil {
				log.Printf("Hijack error: %v", err)
				return
			}
			defer clientConn.Close()
			forwardToSSH(clientConn, "connect")
			return
		}

		// Handle WebSocket upgrade (WS or WSS)
		if websocket.IsWebSocketUpgrade(r) && strings.ToLower(r.Header.Get("Upgrade")) == "websocket" {
			wsConn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				log.Printf("WebSocket upgrade error: %v", err)
				return
			}
			defer wsConn.Close()
			forwardToSSH(&wsConnAdapter{wsConn}, "ws")
			return
		}

		// Fallback for other HTTP requests
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "HTTP/1.1 200 OK\r\n\r\nProxy forwarding...")
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			log.Println("Hijacking not supported")
			http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
			return
		}
		clientConn, _, err := hijacker.Hijack()
		if err != nil {
			log.Printf("Hijack error: %v", err)
			return
		}
		defer clientConn.Close()
		forwardToSSH(clientConn, "http")
	})

	// Create a server to handle HTTP requests
	server := &http.Server{
		Handler: mux,
	}
	if isTLS {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			log.Printf("Failed to load certs: %v", err)
			return
		}
		server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	// Use the existing connection as a fake listener
	listener := &singleConnListener{conn: conn}
	if isTLS {
		server.ServeTLS(listener, certPath, keyPath)
	} else {
		server.Serve(listener)
	}
}

// Adapter to make websocket.Conn implement io.ReadWriteCloser
type wsConnAdapter struct {
	conn *websocket.Conn
}

func (w *wsConnAdapter) Read(p []byte) (int, error) {
	_, msg, err := w.conn.ReadMessage()
	if err != nil {
		return 0, err
	}
	copy(p, msg)
	return len(msg), nil
}

func (w *wsConnAdapter) Write(p []byte) (int, error) {
	err := w.conn.WriteMessage(websocket.BinaryMessage, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *wsConnAdapter) Close() error {
	return w.conn.Close()
}

// singleConnListener wraps a single net.Conn to act as a net.Listener
type singleConnListener struct {
	conn net.Conn
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.conn == nil {
		return nil, io.EOF
	}
	conn := l.conn
	l.conn = nil
	return conn, nil
}

func (l *singleConnListener) Close() error {
	if l.conn != nil {
		return l.conn.Close()
	}
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

func handleTLS(conn net.Conn, port int) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Printf("Failed to load certs: %v", err)
		return
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	tlsConn := tls.Server(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("TLS handshake error: %v", err)
		return
	}
	defer tlsConn.Close()

	handleHTTP(tlsConn, port, true)
}

func forwardToSSH(src io.ReadWriteCloser, proto string) {
	sshConn, err := net.Dial("tcp", "127.0.0.1:22")
	if err != nil {
		log.Printf("Failed to connect to SSH: %v", err)
		return
	}
	defer sshConn.Close()

	log.Printf("Forwarding %s to SSH", proto)
	go io.Copy(src, sshConn)
	io.Copy(sshConn, src)
}

func closePort(scanner *bufio.Scanner) {
	fmt.Print("Enter port to close: ")
	if !scanner.Scan() {
		return
	}
	portStr := strings.TrimSpace(scanner.Text())
	port, err := strconv.Atoi(portStr)
	if err != nil {
		fmt.Println("Invalid port")
		return
	}

	mu.Lock()
	ln, exists := listeners[port]
	mu.Unlock()

	if !exists {
		fmt.Println("Port not open")
		return
	}

	if err := ln.Close(); err != nil {
		log.Printf("Error closing port %d: %v", port, err)
	}

	mu.Lock()
	delete(listeners, port)
	mu.Unlock()
	fmt.Printf("Port %d closed\n", port)
}

func listPorts() {
	mu.Lock()
	defer mu.Unlock()
	if len(listeners) == 0 {
		fmt.Println("No ports open")
		return
	}
	fmt.Println("Open ports:")
	for port := range listeners {
		fmt.Printf("- %d (Multi-protocol)\n", port)
	}
}

func closeAllPorts() {
	mu.Lock()
	defer mu.Unlock()
	for port, ln := range listeners {
		if err := ln.Close(); err != nil {
			log.Printf("Error closing port %d: %v", port, err)
		}
		delete(listeners, port)
	}
}
