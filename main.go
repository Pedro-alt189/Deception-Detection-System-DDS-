package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

/*
Features of this version:
- Logging in Elasticsearch (bulk API). If Elastic is not available, it goes to the local log.
- Complex scanning detector: sliding window, SYN-rate, distinct ports, low-payload probes.
- Simple "protection" from RCE/BufferOverflow: we do not execute data, we cut long payloads, we search for signatures.
- Occupies only available ports; if the port is busy and responds (for example, SSH banner), it lets through.
- Blocklist in memory: after the detector is triggered, we refuse to respond to the source.
*/

type Config struct {
	Interface    string `json:"interface"`
	Ports        []int  `json:"ports"`
	LogFile      string `json:"log_file"`
	SnapLen      int32  `json:"snaplen"`
	Promisc      bool   `json:"promisc"`
	TimeoutMS    int    `json:"timeout_ms"`
	ElasticURL   string `json:"elastic_url"`    // e.g. http://127.0.0.1:9200
	ElasticIndex string `json:"elastic_index"`  // e.g. honeypot
	MaxPayload   int    `json:"max_payload"`    // max bytes to read from remote
	ScanWindowS  int    `json:"scan_window_s"`  // window in seconds for scan heuristics
	ScanPortThresh int  `json:"scan_port_thresh"` // distinct ports threshold
}

var defaultConfig = Config{
	Interface:      "",
	Ports:          []int{22, 80, 443, 12345},
	LogFile:        "",
	SnapLen:        65535,
	Promisc:        true,
	TimeoutMS:      500,
	ElasticURL:     "",
	ElasticIndex:   "honeypot",
	MaxPayload:     4096,
	ScanWindowS:    30,
	ScanPortThresh: 10,
}

type Event struct {
	Time    time.Time              `json:"@timestamp"`
	Type    string                 `json:"type"`
	Source  string                 `json:"source,omitempty"`
	Dest    string                 `json:"dest,omitempty"`
	Port    int                    `json:"port,omitempty"`
	Details map[string]interface{} `json:"details,omitempty"`
}

type ElasticLogger struct {
	url       string
	index     string
	client    *http.Client
	fallback  *log.Logger
	mu        sync.Mutex
	buffer    []Event
	flushSize int
}

func NewElasticLogger(url, index, fallbackPath string) *ElasticLogger {
	var fb *log.Logger
	if fallbackPath == "" {
		fb = log.New(os.Stdout, "", log.LstdFlags)
	} else {
		f, err := os.OpenFile(fallbackPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("cannot open fallback log %v", err)
		}
		fb = log.New(f, "", log.LstdFlags)
	}
	return &ElasticLogger{
		url:       strings.TrimRight(url, "/"),
		index:     index,
		client:    &http.Client{Timeout: 5 * time.Second},
		fallback:  fb,
		buffer:    make([]Event, 0, 100),
		flushSize: 50,
	}
}

func (e *ElasticLogger) logFallback(ev Event) {
	b, _ := json.Marshal(ev)
	e.fallback.Printf("%s", string(b))
}

func (e *ElasticLogger) Send(ev Event) {
	// if no elastic configured, fallback immediately
	if e.url == "" {
		e.logFallback(ev)
		return
	}
	e.mu.Lock()
	e.buffer = append(e.buffer, ev)
	need := len(e.buffer) >= e.flushSize
	e.mu.Unlock()
	if need {
		go e.flush()
	}
}

func (e *ElasticLogger) flush() {
	e.mu.Lock()
	batch := e.buffer
	e.buffer = make([]Event, 0, 100)
	e.mu.Unlock()
	if len(batch) == 0 {
		return
	}
	var buf bytes.Buffer
	for _, ev := range batch {
		meta := map[string]interface{}{"index": map[string]interface{}{}}
		_ = json.NewEncoder(&buf).Encode(meta)
		_ = json.NewEncoder(&buf).Encode(ev)
	}
	// POST to _bulk
	u := fmt.Sprintf("%s/%s/_bulk", e.url, e.index)
	req, err := http.NewRequest("POST", u, &buf)
	if err != nil {
		for _, ev := range batch {
			e.logFallback(ev)
		}
		return
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	resp, err := e.client.Do(req)
	if err != nil || resp.StatusCode >= 300 {
		// fallback: write each
		for _, ev := range batch {
			e.logFallback(ev)
		}
		if resp != nil {
			resp.Body.Close()
		}
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

func (e *ElasticLogger) Close() {
	e.flush()
}

func portInUse(port int) (bool, string, error) {
	// Try to connect - if connect succeeds -> port used by something and responsive.
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 300*time.Millisecond)
	if err == nil {
		// read banner if any
		buf := make([]byte, 256)
		conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, _ := conn.Read(buf)
		banner := strings.TrimSpace(string(buf[:n]))
		conn.Close()
		return true, banner, nil
	}
	// If connection refused, it's not occupied for TCP (could be UDP)
	if opErr, ok := err.(*net.OpError); ok {
		if strings.Contains(opErr.Err.Error(), "refused") {
			return false, "", nil
		}
	}
	// Other errors: timeout => maybe filtered; treat as in use but unknown
	if strings.Contains(err.Error(), "i/o timeout") {
		return true, "", nil
	}
	return false, "", nil
}

func tryOccupy(port int) (*net.TCPListener, *net.UDPConn, error) {
	var tcpLn *net.TCPListener
	var udpConn *net.UDPConn

	tcpAddr := &net.TCPAddr{IP: net.IPv4zero, Port: port}
	ln, err := net.ListenTCP("tcp", tcpAddr)
	if err == nil {
		tcpLn = ln
	}
	udpAddr := &net.UDPAddr{IP: net.IPv4zero, Port: port}
	uc, err2 := net.ListenUDP("udp", udpAddr)
	if err2 == nil {
		udpConn = uc
	}

	if tcpLn == nil && udpConn == nil {
		return nil, nil, errors.New("both binds failed")
	}
	return tcpLn, udpConn, nil
}

type SrcStats struct {
	mu        sync.Mutex
	timestamps []time.Time
	portsSeen map[int]struct{}
	packetCount int
	lastSeen time.Time
}

type Detector struct {
	stats map[string]*SrcStats
	mu    sync.Mutex
	window time.Duration
	portThresh int
	blocked map[string]time.Time
	blockTTL time.Duration
	logger *ElasticLogger
}

func NewDetector(window time.Duration, portThresh int, logger *ElasticLogger) *Detector {
	return &Detector{
		stats: make(map[string]*SrcStats),
		window: window,
		portThresh: portThresh,
		blocked: make(map[string]time.Time),
		blockTTL: 10 * time.Minute,
		logger: logger,
	}
}

func (d *Detector) recordPacket(srcIP string, dport int, synOnly bool, payloadLen int) {
	d.mu.Lock()
	st, ok := d.stats[srcIP]
	if !ok {
		st = &SrcStats{portsSeen: make(map[int]struct{})}
		d.stats[srcIP] = st
	}
	d.mu.Unlock()

	st.mu.Lock()
	now := time.Now()
	st.timestamps = append(st.timestamps, now)
	st.portsSeen[dport] = struct{}{}
	st.packetCount++
	st.lastSeen = now
	// trim timestamps older than window
	cut := now.Add(-d.window)
	i := 0
	for ; i < len(st.timestamps); i++ {
		if st.timestamps[i].After(cut) {
			break
		}
	}
	if i > 0 {
		st.timestamps = append([]time.Time{}, st.timestamps[i:]...)
	}
	// heuristic checks
	distinct := len(st.portsSeen)
	count := len(st.timestamps)
	st.mu.Unlock()

	if distinct >= d.portThresh && count >= (d.portThresh*2) {
		// port scanning detected
		d.raiseAlert(srcIP, "port_scan", map[string]interface{}{
			"distinct_ports": distinct,
			"recent_packets": count,
		})
		d.block(srcIP)
		return
	}

	// SYN flood heuristic: if many packets in short time
	if synOnly && count >= 50 {
		d.raiseAlert(srcIP, "syn_flood", map[string]interface{}{
			"recent_packets": count,
		})
		d.block(srcIP)
		return
	}

	// small payload repeated to many ports -> scan
	if payloadLen == 0 && distinct >= 15 {
		d.raiseAlert(srcIP, "null_payload_scan", map[string]interface{}{
			"distinct_ports": distinct,
		})
		d.block(srcIP)
		return
	}
}

func (d *Detector) raiseAlert(ip, typ string, details map[string]interface{}) {
	ev := Event{
		Time: time.Now(),
		Type: "alert",
		Source: ip,
		Details: map[string]interface{}{
			"alert_type": typ,
			"meta": details,
		},
	}
	d.logger.Send(ev)
}

func (d *Detector) block(ip string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.blocked[ip] = time.Now().Add(d.blockTTL)
	// optional: try to add iptables drop (if permitted) -- best-effort
	go func(ip string) {
		cmd := exec.Command("sh", "-c", fmt.Sprintf("iptables -I INPUT -s %s -j DROP", ip))
		_ = cmd.Run() // ignore errors
	}(ip)
}

func (d *Detector) isBlocked(ip string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	exp, ok := d.blocked[ip]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(d.blocked, ip)
		return false
	}
	return true
}

func suspiciousPayload(b []byte) (bool, string) {
	// long payload -> suspect buffer overflow or binary blob
	if len(b) > 8192 {
		return true, "oversize_payload"
	}
	// common RCE patterns: system calls, evals, base64 shell stagers, NOP sled
	s := strings.ToLower(string(b))
	patterns := []string{"eval(", "exec(", "system(", "popen(", "perl -e", "python -c", "bash -c", "sh -c", "cmd.exe", "powershell", "socket.socket(", "wget http", "curl http"}
	for _, p := range patterns {
		if strings.Contains(s, p) {
			return true, "rce_pattern:" + p
		}
	}
	// binary NOP-sled heuristic
	if bytes.Count(b, []byte{0x90}) > 50 {
		return true, "nop_sled_like"
	}
	// suspicious high-entropy content (simple approx: many non-ascii)
	nonAscii := 0
	for _, c := range b {
		if c < 9 || c > 126 {
			nonAscii++
		}
	}
	if nonAscii > len(b)/2 && len(b) > 200 {
		return true, "binary_blob"
	}
	return false, ""
}

type Occupied struct {
	TCP []*net.TCPListener
	UDP []*net.UDPConn
}

func handleTCP(conn net.Conn, cfg *Config, logger *ElasticLogger, det *Detector) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	ip, _, _ := net.SplitHostPort(remote)
	if det.isBlocked(ip) {
		// politely drop (no response)
		logger.Send(Event{Time: time.Now(), Type: "blocked_connection", Source: ip, Dest: conn.LocalAddr().String()})
		return
	}
	logger.Send(Event{Time: time.Now(), Type: "tcp_accept", Source: ip, Dest: conn.LocalAddr().String()})
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	max := cfg.MaxPayload
	if max <= 0 {
		max = 4096
	}
	buf := make([]byte, max)
	n, err := conn.Read(buf)
	if err != nil {
		logger.Send(Event{Time: time.Now(), Type: "tcp_read_err", Source: ip, Dest: conn.LocalAddr().String(), Details: map[string]interface{}{"err": err.Error()}})
		return
	}
	payload := buf[:n]
	// Check suspicious
	if ok, why := suspiciousPayload(payload); ok {
		logger.Send(Event{Time: time.Now(), Type: "suspicious_payload", Source: ip, Dest: conn.LocalAddr().String(), Port: 0, Details: map[string]interface{}{"reason": why, "len": len(payload)}})
		det.block(ip)
		// do not process; close connection
		return
	}
	// safe logging: hash the payload (avoid storing raw large content)
	h := sha1.Sum(payload)
	logger.Send(Event{Time: time.Now(), Type: "tcp_payload", Source: ip, Dest: conn.LocalAddr().String(), Details: map[string]interface{}{"len": len(payload), "sha1": fmt.Sprintf("%x", h)}})

	// offer fake banner for services that expect it
	_ = writeSafe(conn, []byte("220 honeypot service\r\n"))
}

func writeSafe(conn net.Conn, data []byte) error {
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err := conn.Write(data)
	if err != nil {
		// ignore write errors
		return err
	}
	return nil
}

func tcpListenerLoop(ln *net.TCPListener, cfg *Config, logger *ElasticLogger, det *Detector, ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	if ln == nil {
		return
	}
	for {
		ln.SetDeadline(time.Now().Add(1 * time.Second))
		conn, err := ln.Accept()
		select {
		case <-ctx.Done():
			logger.Send(Event{Time: time.Now(), Type: "tcp_listener_shutdown", Details: map[string]interface{}{"addr": ln.Addr().String()}})
			return
		default:
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			logger.fallback.Printf("tcp accept error: %v", err)
			continue
		}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			handleTCP(c, cfg, logger, det)
		}(conn)
	}
}

func udpListenerLoop(conn *net.UDPConn, cfg *Config, logger *ElasticLogger, det *Detector, ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	if conn == nil {
		return
	}
	buf := make([]byte, 65535)
	for {
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, addr, err := conn.ReadFromUDP(buf)
		select {
		case <-ctx.Done():
			logger.Send(Event{Time: time.Now(), Type: "udp_listener_shutdown", Details: map[string]interface{}{"addr": conn.LocalAddr().String()}})
			return
		default:
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			logger.fallback.Printf("udp read error: %v", err)
			continue
		}
		ip := addr.IP.String()
		if det.isBlocked(ip) {
			logger.Send(Event{Time: time.Now(), Type: "udp_blocked", Source: ip, Dest: conn.LocalAddr().String()})
			continue
		}
		// payload safety
		payload := make([]byte, n)
		copy(payload, buf[:n])
		if ok, why := suspiciousPayload(payload); ok {
			logger.Send(Event{Time: time.Now(), Type: "suspicious_payload_udp", Source: ip, Dest: conn.LocalAddr().String(), Details: map[string]interface{}{"reason": why}})
			det.block(ip)
			continue
		}
		h := sha1.Sum(payload)
		logger.Send(Event{Time: time.Now(), Type: "udp_payload", Source: ip, Dest: conn.LocalAddr().String(), Port: addr.Port, Details: map[string]interface{}{"len": n, "sha1": fmt.Sprintf("%x", h)}})
	}
}

func packetCaptureLoop(cfg *Config, logger *ElasticLogger, det *Detector, ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	if cfg.Interface == "" {
		logger.Send(Event{Time: time.Now(), Type: "pcap_skipped", Details: map[string]interface{}{"reason": "no interface"}})
		return
	}
	timeout := time.Duration(cfg.TimeoutMS) * time.Millisecond
	handle, err := pcap.OpenLive(cfg.Interface, cfg.SnapLen, cfg.Promisc, timeout)
	if err != nil {
		logger.Send(Event{Time: time.Now(), Type: "pcap_error", Details: map[string]interface{}{"err": err.Error()}})
		return
	}
	defer handle.Close()
	logger.Send(Event{Time: time.Now(), Type: "pcap_start", Details: map[string]interface{}{"iface": cfg.Interface}})
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	ch := packetSource.Packets()
	for {
		select {
		case <-ctx.Done():
			logger.Send(Event{Time: time.Now(), Type: "pcap_stop"})
			return
		case packet, ok := <-ch:
			if !ok {
				logger.Send(Event{Time: time.Now(), Type: "pcap_closed"})
				return
			}
			go func(p gopacket.Packet) {
				netLayer := p.NetworkLayer()
				transport := p.TransportLayer()
				srcIP, dstIP := "?", "?"
				if netLayer != nil {
					switch n := netLayer.(type) {
					case *layers.IPv4:
						srcIP = n.SrcIP.String()
						dstIP = n.DstIP.String()
					case *layers.IPv6:
						srcIP = n.SrcIP.String()
						dstIP = n.DstIP.String()
					}
				}
				// ICMP
				if p.Layer(layers.LayerTypeICMPv4) != nil || p.Layer(layers.LayerTypeICMPv6) != nil {
					logger.Send(Event{Time: time.Now(), Type: "icmp", Source: srcIP, Dest: dstIP})
					det.recordPacket(srcIP, 0, false, 0)
					return
				}
				if transport != nil {
					switch t := transport.(type) {
					case *layers.TCP:
						sport := int(t.SrcPort)
						dport := int(t.DstPort)
						payloadLen := len(t.Payload)
						synOnly := t.SYN && !t.ACK && payloadLen == 0
						logger.Send(Event{Time: time.Now(), Type: "pcap_tcp", Source: srcIP, Dest: dstIP, Port: dport, Details: map[string]interface{}{"flags": t.Flags.String(), "payload": payloadLen}})
						det.recordPacket(srcIP, dport, synOnly, payloadLen)
					case *layers.UDP:
						dport := int(t.DstPort)
						logger.Send(Event{Time: time.Now(), Type: "pcap_udp", Source: srcIP, Dest: dstIP, Port: dport, Details: map[string]interface{}{"payload": len(t.Payload)}})
						det.recordPacket(srcIP, dport, false, len(t.Payload))
					default:
						logger.Send(Event{Time: time.Now(), Type: "pcap_other", Source: srcIP, Dest: dstIP})
					}
				} else {
					// ARP or other
					if p.Layer(layers.LayerTypeARP) != nil {
						logger.Send(Event{Time: time.Now(), Type: "arp", Details: map[string]interface{}{"raw": p.Layer(layers.LayerTypeARP).LayerContents()}})
					} else {
						logger.Send(Event{Time: time.Now(), Type: "pcap_unknown"})
					}
				}
			}(packet)
		}
	}
}

func loadConfig(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, err
	}
	// apply defaults
	if cfg.SnapLen == 0 {
		cfg.SnapLen = defaultConfig.SnapLen
	}
	if cfg.TimeoutMS == 0 {
		cfg.TimeoutMS = defaultConfig.TimeoutMS
	}
	if cfg.MaxPayload == 0 {
		cfg.MaxPayload = defaultConfig.MaxPayload
	}
	if cfg.ScanWindowS == 0 {
		cfg.ScanWindowS = defaultConfig.ScanWindowS
	}
	if cfg.ScanPortThresh == 0 {
		cfg.ScanPortThresh = defaultConfig.ScanPortThresh
	}
	return cfg, nil
}

func main() {
	cfgPath := flag.String("config", "config.json", "path to config.json")
	printCfg := flag.Bool("print-config", false, "print default config")
	flag.Parse()

	if *printCfg {
		b, _ := json.MarshalIndent(defaultConfig, "", "  ")
		fmt.Println(string(b))
		return
	}

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Printf("failed to load config %s: %v; using defaults", *cfgPath, err)
		cfg = defaultConfig
	}

	logger := NewElasticLogger(cfg.ElasticURL, cfg.ElasticIndex, cfg.LogFile)
	defer logger.Close()

	logger.Send(Event{Time: time.Now(), Type: "startup", Details: map[string]interface{}{"ports_configured": cfg.Ports, "iface": cfg.Interface}})

	ctx, cancel := context.WithCancel(context.Background())
	wg := &sync.WaitGroup{}

	detector := NewDetector(time.Duration(cfg.ScanWindowS)*time.Second, cfg.ScanPortThresh, logger)

	occupied := &Occupied{}
	// Attempt to take ports; if port busy but responsive (banner) -> skip
	for _, p := range cfg.Ports {
		inUse, banner, perr := portInUse(p)
		if perr == nil && inUse {
			// service active — skip occupying: respect existing service
			logger.Send(Event{Time: time.Now(), Type: "port_in_use", Port: p, Details: map[string]interface{}{"banner": banner}})
			continue
		}
		tcpLn, udpConn, err := tryOccupy(p)
		if err != nil {
			logger.Send(Event{Time: time.Now(), Type: "port_bind_failed", Port: p, Details: map[string]interface{}{"err": err.Error()}})
			continue
		}
		if tcpLn != nil {
			occupied.TCP = append(occupied.TCP, tcpLn)
			wg.Add(1)
			go tcpListenerLoop(tcpLn, &cfg, logger, detector, ctx, wg)
			logger.Send(Event{Time: time.Now(), Type: "tcp_bound", Port: p})
		}
		if udpConn != nil {
			occupied.UDP = append(occupied.UDP, udpConn)
			wg.Add(1)
			go udpListenerLoop(udpConn, &cfg, logger, detector, ctx, wg)
			logger.Send(Event{Time: time.Now(), Type: "udp_bound", Port: p})
		}
	}

	// If none bound, log and continue (pcap may still run)
	if len(occupied.TCP) == 0 && len(occupied.UDP) == 0 {
		logger.Send(Event{Time: time.Now(), Type: "no_ports_bound", Details: map[string]interface{}{"note": "no available ports bound; check permissions or occupancies"}})
	}

	// start pcap
	wg.Add(1)
	go packetCaptureLoop(&cfg, logger, detector, ctx, wg)

	// admin console
	wg.Add(1)
	go func() {
		defer wg.Done()
		in := bufio.NewScanner(os.Stdin)
		for in.Scan() {
			line := strings.TrimSpace(in.Text())
			if line == "" {
				continue
			}
			switch line {
			case "q", "quit", "exit":
				logger.Send(Event{Time: time.Now(), Type: "admin_exit"})
				cancel()
				return
			case "status":
				logger.Send(Event{Time: time.Now(), Type: "admin_status", Details: map[string]interface{}{
					"tcp_listeners": len(occupied.TCP),
					"udp_conns":     len(occupied.UDP),
				}})
			default:
				logger.Send(Event{Time: time.Now(), Type: "admin_cmd", Details: map[string]interface{}{"cmd": line}})
			}
		}
	}()

	// signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Send(Event{Time: time.Now(), Type: "signal", Details: map[string]interface{}{"sig": sig.String()}})
		cancel()
	}()

	wg.Wait()
	// cleanup
	for _, ln := range occupied.TCP {
		ln.Close()
	}
	for _, uc := range occupied.UDP {
		uc.Close()
	}
	logger.Send(Event{Time: time.Now(), Type: "shutdown"})
}
