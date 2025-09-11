package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
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

	// Sniff first 4 bytes to detect protocol
	buf := make([]byte, 4)
	n, err := conn.Read(buf)
	if err != nil || n < 2 {
		log.Printf("Failed to read initial bytes: %v", err)
		return
	}

	protocol := detectProtocol(buf[:n])
	log.Printf("Detected protocol: %s from %s", protocol, conn.RemoteAddr())

	switch protocol {
	case "SOCKS5":
		handleSOCKS5(conn)
	case "HTTP":
		handleHTTP(conn, port)
	case "TLS":
		handleTLS(conn, port)
	default:
		log.Printf("Unknown protocol")
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

func handleSOCKS5(conn net.Conn) {
	// Basic SOCKS5 handler: Auth (no auth), then connect to SSH
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}
	if buf[0] != 0x05 {
		conn.Write([]byte{0x05, 0x01, 0x00})
		return
	}
	// No auth response
	conn.Write([]byte{0x05, 0x00})

	// Read connect request
	n, err = conn.Read(buf)
	if err != nil || buf[0] != 0x05 || buf[1] != 0x01 {
		return
	}
	// Parse addr (simple: assume IPv4)
	ip := net.IP(buf[4:8])
	port := (uint16(buf[8]) << 8) | uint16(buf[9])
	target := fmt.Sprintf("%s:%d", ip, port)

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

func handleHTTP(conn net.Conn, port int) {
	// Upgrade to HTTP connection for WebSocket or CONNECT
	tlsConn := conn // Plain HTTP
	handleHTTPCommon(tlsConn.(*net.TCPConn), false, port)
}

func handleTLS(conn net.Conn, port int) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Printf("Failed to load certs: %v", err)
		return
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	tlsConn := tls.Server(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("TLS handshake error: %v", err)
		return
	}
	defer tlsConn.Close()

	// Now treat as HTTP over TLS
	handleHTTPCommon(tlsConn, true, port)
}

func handleHTTPCommon(conn net.Conn, isTLS bool, port int) {
	// Read HTTP request
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}
	reqStr := string(buf[:n])
	log.Printf("HTTP request: %s", reqStr)

	// Parse request (simple parser)
	lines := strings.Split(reqStr, "\r\n")
	if len(lines) == 0 {
		return
	}
	firstLine := lines[0]
	if strings.Contains(firstLine, "Upgrade: websocket") {
		// WebSocket upgrade
		wsConn, err := upgrader.Upgrade(conn, nil, nil)
		if err != nil {
			log.Printf("WS upgrade error: %v", err)
			return
		}
		defer wsConn.Close()
		forwardToSSH(wsConn, "ws")
		return
	} else if strings.HasPrefix(firstLine, "CONNECT ") {
		// SOCKS-like via CONNECT
		conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		hijacker, ok := conn.(interface{ Hijack() (net.Conn, *bufio.ReadWriter, error) })
		if !ok {
			return
		}
		clientConn, _, _ := hijacker.Hijack()
		defer clientConn.Close()
		forwardToSSH(clientConn, "connect")
		return
	}
	// Fallback: Treat as HTTP and forward
	conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\nProxy forwarding..."))
	forwardToSSH(conn, "http")
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ln.Close()

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
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ln.Close()
		delete(listeners, port)
	}
}
