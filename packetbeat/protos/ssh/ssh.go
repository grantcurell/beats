// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.
package ssh

import (
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
// There are two streams in any conversation. These represent the two different
// directions traffic could flow.
type connection struct {
	// [0] is the client's SSH stream, [1] is server's
	streams [2]*stream
	trans   transactions
}

// Uni-directional tcp stream state for parsing messages.
// TODO: I think this stream is used for temporary storage while they construct
// one back and forth conversation
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
TODO NEED TO FIGURE OUT WHY THIS IS BROKEN
func (s *stream) PrepareForNewMessage() {
	parser := &s.parser
	s.Stream.Reset()
	parser.reset()
}*/

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
// This is called by tcp.go after the tcp header is read and deencapsulated
func (sp *sshPlugin) Parse(
	pkt *protos.Packet,
	tcptuple *common.TCPTuple,
	dir uint8,
	private protos.ProtocolData,
) protos.ProtocolData {
	//debug.PrintStack()
	defer logp.Recover("Parse sshPlugin exception")

	conn := sp.ensureConnection(private)

	// Printing this on HTTP gets you something like this: &{0xc0000c6598 [] 0 0 0 <nil>}
	// When there is actually data the data field blows up. It's the one with the brackets

	// This grabs all streams for the direction in which the traffic is flowing.
	st := conn.streams[dir]
	// EXTRA After running: (*ssh.stream)(<nil>)

	// This figures out if a conversation already exists for this. If not
	// it starts a new conversation
	// EXTRA I DON'T THINK THE BELOW IS NECESSARY. I THINK PACKETBEAT
	// NATIVELY TAKES CARE OF THIS
	// conversation = find_or_create_conversation(pinfo);
	// global_data = (struct ssh_flow_data *)conversation_get_proto_data(conversation, proto_ssh);

	if st == nil {
		st = &stream{} // Create a new stream if one doesn't already exist
		st.parser.init(&sp.parserConfig, func(msg *message) error {
			return conn.trans.onMessage(tcptuple.IPPort(), dir, msg)
		})
		conn.streams[dir] = st
	} else {

	}

	if err := st.parser.feed(sp, pkt.Ts, pkt.Payload, dir); err != nil {
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
