package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/go-yaml/yaml"
	"github.com/miekg/dns"
)

type Config struct {
	Upstream string `yaml:"upstream"`
	Cert     string `yaml:"cert"`
	Key      string `yaml:"key"`
	Domain   string `yaml:"domain"`
	Port     int    `yaml:"port"`
}

func main() {
	// Read config file
	config, err := readConfig("config.yml")
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)
	}

	// Create TLS configuration
	cert, err := tls.LoadX509KeyPair(config.Cert, config.Key)
	if err != nil {
		log.Fatalf("Failed to load TLS certificate: %v", err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	// Start server
	addr := fmt.Sprintf("%s:%d", config.Domain, config.Port)
	listener, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
	log.Printf("Listening on %s", addr)

	// Handle incoming connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		go handleConnection(conn, config.Upstream)
	}
}

func readConfig(filename string) (*Config, error) {
	// Read file
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// Parse YAML
	config := &Config{}
	err = yaml.Unmarshal(data, config)
	if err != nil {
		return nil, err
	}

	return config, nil
}

func handleConnection(conn net.Conn, upstream string) {
	defer conn.Close()

	// Set deadline for read/write operations
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	// Read query
	query, err := readDNSMessage(conn)
	if err != nil {
		log.Printf("Failed to read query: %v", err)
		return
	}

	// Check query ID
	if query.Id == 0 {
		log.Printf("Invalid query ID")
		return
	}

	// Check question count
	if len(query.Question) != 1 {
		log.Printf("Invalid question count")
		return
	}

	// Get question
	question := query.Question[0]

	// Create DNS client
	var client *dns.Client
	if strings.HasPrefix(upstream, "tls://") {
		// DNS over TLS
		config := &tls.Config{ServerName: question.Name}
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		conn, err := tls.DialWithDialer(dialer, "tcp", upstream[6:], config)
		if err != nil {
			log.Printf("Failed to connect to upstream server: %v", err)
			return
		}
		defer conn.Close()
		client = &dns.Client{Net: "tcp-tls", TLSConfig: config}
	} else if strings.HasPrefix(upstream, "tcp://") {
		// TCP DNS
		client = &dns.Client{Net: "tcp"}
	} else {
		// UDP DNS
		client = &dns.Client{Net: "udp"}
	}

	config, err := readConfig("config.yml")
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)

	}
	key, err := os.ReadFile(config.Key)
	if err != nil {
		log.Fatalf("Failed to read key file: %v", err)
	}

	// Set EDNS0 options
	opt := &dns.OPT{
		Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT},
		Option: []dns.EDNS0{
			&dns.EDNS0_SUBNET{
				Code:          dns.EDNS0SUBNET,
				Family:        1, // IP4
				SourceNetmask: 24,
				Address:       conn.RemoteAddr().(*net.TCPAddr).IP,
			},
			&dns.EDNS0_COOKIE{
				Code: dns.EDNS0COOKIE,
				// Generate Cookie
				Cookie: generateDNSCookie(conn.RemoteAddr().(*net.TCPAddr).IP, key),
			},
		},
	}

	// Set DNSSEC OK bit
	if question.Qclass == dns.ClassINET {
		opt.SetDo()
	}

	// Create query message
	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               query.Id,
			RecursionDesired: true,
		},
		Question: []dns.Question{question},
		Extra:    []dns.RR{opt},
	}

	// Send query
	response, _, err := client.Exchange(msg, upstream)
	if err != nil {
		log.Printf("Failed to send query: %v", err)
		return
	}

	// Write response
	err = writeDNSMessage(conn, response)
	if err != nil {
		log.Printf("Failed to write response: %v", err)
		return
	}
}

func readDNSMessage(conn io.Reader) (*dns.Msg, error) {
	// Read message length
	var length uint16
	err := binary.Read(conn, binary.BigEndian, &length)
	if err != nil {
		return nil, err
	}

	// Read message
	buf := make([]byte, length)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}

	// Parse message
	msg := &dns.Msg{}
	err = msg.Unpack(buf)
	if err != nil {
		return nil, err
	}

	return msg, nil
}

func writeDNSMessage(conn io.Writer, msg *dns.Msg) error {
	// Pack message
	buf, err := msg.Pack()
	if err != nil {
		return err
	}

	// Write message length
	err = binary.Write(conn, binary.BigEndian, uint16(len(buf)))
	if err != nil {
		return err
	}

	// Write message
	_, err = conn.Write(buf)
	if err != nil {
		return err
	}

	return nil
}

func generateDNSCookie(clientIP net.IP, serverKey []byte) string {
	// Create HMAC-SHA1 hash of client IP and server key
	mac := hmac.New(sha1.New, serverKey)
	mac.Write(clientIP)
	hash := mac.Sum(nil)

	// Encode hash as base64
	cookie := make([]byte, base64.StdEncoding.EncodedLen(len(hash)))
	base64.StdEncoding.Encode(cookie, hash)

	return string(cookie)
}
