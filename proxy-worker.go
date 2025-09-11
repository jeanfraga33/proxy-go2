package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var (
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true }, // Allow all origins for simplicity
	}

	servers = make(map[int]*http.Server)
	mu      sync.Mutex
)

func main() {
	menu()
}

func menu() {
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Println("\n=== Proxy Menu ===")
		fmt.Println("1. Open port (HTTP and HTTPS/WSS)")
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
	}
	if err := scanner.Err(); err != nil {
		log.Fatal("Scanner error:", err)
	}
}

func generateSelfSignedCert(keyFile, certFile string) error {
	// Remove existing files if they exist
	if err := os.Remove(keyFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("error removing key file: %v", err)
	}
	if err := os.Remove(certFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("error removing cert file: %v", err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("error generating private key: %v", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("error generating serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Proxy Server"},
			CommonName:   "localhost",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	template.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1), net.ParseIP("::1")}
	template.DNSNames = []string{"localhost"}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("error creating certificate: %v", err)
	}

	// Encode private key
	keyOut, err := os.Create(keyFile)
	if err != nil {
		return fmt.Errorf("error creating key file: %v", err)
	}
	defer keyOut.Close()
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	// Encode certificate
	certOut, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("error creating cert file: %v", err)
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	return nil
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
	if _, exists := servers[port]; exists {
		mu.Unlock()
		fmt.Println("Port already open")
		return
	}
	mu.Unlock()

	// Generate certificates for HTTPS/WSS
	certFile := "cert.pem"
	keyFile := "key.pem"
	if err := generateSelfSignedCert(keyFile, certFile); err != nil {
		fmt.Printf("Error generating self-signed certificate: %v\n", err)
		return
	}
	fmt.Println("Self-signed certificate generated successfully.")

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleProxyRequest)

	// HTTPS/WSS server
	serverTLS := &http.Server{
		Addr:      ":" + portStr,
		Handler:   mux,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}

	// HTTP server (non-TLS)
	serverHTTP := &http.Server{
		Addr:    ":" + portStr,
		Handler: mux,
	}

	mu.Lock()
	servers[port] = serverTLS // Store TLS server for management
	mu.Unlock()

	// Start HTTP server in background
	go func() {
		if err := serverHTTP.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server on port %d error: %v", port, err)
		}
	}()

	// Start HTTPS/WSS server in background
	go func() {
		if err := serverTLS.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTPS/WSS server on port %d error: %v", port, err)
		}
	}()

	fmt.Printf("Port %d opened (HTTP and HTTPS/WSS support) and listening in background\n", port)
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
	server, exists := servers[port]
	mu.Unlock()

	if !exists {
		fmt.Println("Port not open")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Error shutting down server on port %d: %v", port, err)
	}
	mu.Lock()
	delete(servers, port)
	mu.Unlock()
	fmt.Printf("Port %d closed\n", port)
}

func listPorts() {
	mu.Lock()
	defer mu.Unlock()
	if len(servers) == 0 {
		fmt.Println("No ports open")
		return
	}
	fmt.Println("Open ports:")
	for port := range servers {
		fmt.Printf("- %d (HTTP and HTTPS/WSS)\n", port)
	}
}

func closeAllPorts() {
	mu.Lock()
	defer mu.Unlock()
	for port, server := range servers {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Error closing port %d: %v", port, err)
		}
		delete(servers, port)
	}
}

func handleProxyRequest(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received request: Method=%s, URL=%s, Headers=%v, RemoteAddr=%s", r.Method, r.URL, r.Header, r.RemoteAddr)

	if r.Method == "CONNECT" {
		// Handle SOCKS-like tunneling via HTTP CONNECT
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

		// Forward to OpenSSH (localhost:22) for authentication
		sshConn, err := net.Dial("tcp", "127.0.0.1:22")
		if err != nil {
			log.Printf("Failed to connect to SSH: %v", err)
			return
		}
		defer sshConn.Close()

		// Bidirectional pipe - connection stays open until client disconnects
		go io.Copy(clientConn, sshConn)
		io.Copy(sshConn, clientConn)
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

		// Forward to OpenSSH (localhost:22) for authentication
		sshConn, err := net.Dial("tcp", "127.0.0.1:22")
		if err != nil {
			log.Printf("Failed to connect to SSH: %v", err)
			return
		}
		defer sshConn.Close()

		// Bidirectional forwarding: WS binary messages <-> raw TCP bytes
		go forwardTCPToWS(wsConn, sshConn)
		forwardWSToTCP(wsConn, sshConn)
		return
	}

	// Fallback for all other requests
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

	// Forward to OpenSSH (localhost:22) for authentication
	sshConn, err := net.Dial("tcp", "127.0.0.1:22")
	if err != nil {
		log.Printf("Failed to connect to SSH: %v", err)
		return
	}
	defer sshConn.Close()

	// Bidirectional pipe - connection stays open until client disconnects
	go io.Copy(clientConn, sshConn)
	io.Copy(sshConn, clientConn)
}

func forwardWSToTCP(wsConn *websocket.Conn, tcpConn net.Conn) {
	defer tcpConn.Close()
	for {
		_, msg, err := wsConn.ReadMessage()
		if err != nil {
			break
		}
		_, err = tcpConn.Write(msg)
		if err != nil {
			break
		}
	}
}

func forwardTCPToWS(wsConn *websocket.Conn, tcpConn net.Conn) {
	defer tcpConn.Close()
	buf := make([]byte, 1024)
	for {
		n, err := tcpConn.Read(buf)
		if err != nil || n == 0 {
			break
		}
		if err := wsConn.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
			break
		}
	}
}
