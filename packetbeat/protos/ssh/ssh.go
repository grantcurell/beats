package ssh

import (
	"fmt"
	"time"

	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"

	"github.com/elastic/beats/packetbeat/protos"
	"github.com/elastic/beats/packetbeat/protos/tcp"
)

// sshPlugin application level protocol analyzer plugin
type sshPlugin struct {
	ports        protos.PortsConfig
	parserConfig parserConfig
	transConfig  transactionConfig
	pub          transPub
}

// Application Layer tcp stream data to be stored on tcp connection context.
type connection struct {
	streams [2]*stream
	trans   transactions
}

// Uni-directional tcp stream state for parsing messages.
type stream struct {
	parser parser
}

var (
	debugf = logp.MakeDebug("ssh")

	// use isDebug/isDetailed to guard debugf/detailedf to minimize allocations
	// (garbage collection) when debug log is disabled.
	isDebug = false
)

func init() {

	// Register your newly created protocol with Packetbeat. This is what makes
	// your protocol available for use.
	protos.Register("ssh", New)
}

// New create and initializes a new ssh protocol analyzer instance. This is all
// boilerplate code and for the most part will not require modification.
func New(
	testMode bool,
	results protos.Reporter,
	cfg *common.Config,
) (protos.Plugin, error) {
	p := &sshPlugin{}
	config := defaultConfig
	if !testMode {
		if err := cfg.Unpack(&config); err != nil {
			return nil, err
		}
	}

	if err := p.init(results, &config); err != nil {
		return nil, err
	}
	return p, nil
}

// TODO also appears to be boilerplate code
func (sp *sshPlugin) init(results protos.Reporter, config *sshConfig) error {
	if err := sp.setFromConfig(config); err != nil {
		return err
	}
	sp.pub.results = results

	isDebug = logp.IsDebug("http")
	return nil
}

// TODO more boilerplate code?
func (sp *sshPlugin) setFromConfig(config *sshConfig) error {

	// set module configuration
	if err := sp.ports.Set(config.Ports); err != nil {
		return err
	}

	// set parser configuration
	parser := &sp.parserConfig
	parser.maxBytes = tcp.TCPMaxDataInStream

	// set transaction correlator configuration
	trans := &sp.transConfig
	trans.transactionTimeout = config.TransactionTimeout

	// set transaction publisher configuration
	pub := &sp.pub
	pub.sendRequest = config.SendRequest
	pub.sendResponse = config.SendResponse

	return nil
}

/*
func (s *stream) PrepareForNewMessage() {
	parser := &s.parser
	s.Stream.Reset()
	parser.reset()
}
*/

// ConnectionTimeout returns the per stream connection timeout.
// Return <=0 to set default tcp module transaction timeout.
func (sp *sshPlugin) ConnectionTimeout() time.Duration {
	return sp.transConfig.transactionTimeout
}

// GetPorts returns the ports numbers packets shall be processed for.
func (sp *sshPlugin) GetPorts() []int {
	return sp.ports.Ports
}

// Parse processes a TCP packet. Return nil if connection
// state shall be dropped (e.g. parser not in sync with tcp stream)
func (sp *sshPlugin) Parse(
	pkt *protos.Packet,
	tcptuple *common.TCPTuple,
	dir uint8,
	private protos.ProtocolData,
) protos.ProtocolData {
	//debug.PrintStack()
	defer logp.Recover("Parse sshPlugin exception")

	conn := sp.ensureConnection(private)
	fmt.Println(dir)
	st := conn.streams[dir]
	fmt.Println(st) // TODO: This keeps coming out NIL

	// This is some boilerplate failure code in the event that the TCP stream
	// is empty
	if st == nil {
		st = &stream{}
		st.parser.init(&sp.parserConfig, func(msg *message) error {
			return conn.trans.onMessage(tcptuple.IPPort(), dir, msg)
		})
		conn.streams[dir] = st
	} else {
		fmt.Println(st.parser.message)
	}

	if err := st.parser.feed(pkt.Ts, pkt.Payload); err != nil {
		debugf("%v, dropping TCP stream for error in direction %v.", err, dir)
		sp.onDropConnection(conn)
		return nil
	}
	return conn
}

// ReceivedFin handles TCP-FIN packet.
func (sp *sshPlugin) ReceivedFin(
	tcptuple *common.TCPTuple, dir uint8,
	private protos.ProtocolData,
) protos.ProtocolData {
	return private
}

// GapInStream handles lost packets in tcp-stream.
func (sp *sshPlugin) GapInStream(tcptuple *common.TCPTuple, dir uint8,
	nbytes int,
	private protos.ProtocolData,
) (protos.ProtocolData, bool) {
	conn := getConnection(private)
	if conn != nil {
		sp.onDropConnection(conn)
	}

	return nil, true
}

// onDropConnection processes and optionally sends incomplete
// transaction in case of connection being dropped due to error
func (sp *sshPlugin) onDropConnection(conn *connection) {
}

func (sp *sshPlugin) ensureConnection(private protos.ProtocolData) *connection {
	conn := getConnection(private)
	if conn == nil {
		conn = &connection{}
		conn.trans.init(&sp.transConfig, sp.pub.onTransaction)
	}
	return conn
}

func (conn *connection) dropStreams() {
	conn.streams[0] = nil
	conn.streams[1] = nil
}

func getConnection(private protos.ProtocolData) *connection {
	if private == nil {
		return nil
	}

	priv, ok := private.(*connection)
	if !ok {
		logp.Warn("ssh connection type error")
		return nil
	}
	if priv == nil {
		logp.Warn("Unexpected: ssh connection data not set")
		return nil
	}
	return priv
}
