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
type connection struct {
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

type ssh_peer_data struct {
	counter uint

	frame_version_start uint32
	frame_version_end   uint32

	frame_key_start      int32
	frame_key_end        int32
	frame_key_end_offset int

	kex_proposal *uint8

	/* For all subsequent proposals,
	[0] is client-to-server and [1] is server-to-client. */
	CLIENT_TO_SERVER_PROPOSAL int `0`
	SERVER_TO_CLIENT_PROPOSAL int `1`

	mac_proposals [2]*uint8
	mac           *uint8
	mac_length    int

	enc_proposals [2]*uint8
	enc           *uint8

	comp_proposals [2]*uint8
	comp           *uint8

	length_is_plaintext int
}

type ssh_flow_data struct {
	version uint

	kex *uint8
	//TODO int   (*kex_specific_dissector)(uint8 msg_code, tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree);

	/* [0] is client's, [1] is server's */
	CLIENT_PEER_DATA int `0`
	SERVER_PEER_DATA int `1`
	peer_data        [2]ssh_peer_data
}

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

func (s *stream) PrepareForNewMessage() {
	parser := &s.parser
	s.Stream.Reset()
	parser.reset()
}

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

	/*
		The arguments to this function look like the below.
		(*protos.Packet)(0xc0011e6cc0)({
		Ts: (time.Time) 2018-12-14 10:52:41.969161 -0600 CST,
		Tuple: (common.IPPortTuple) IpPortTuple src[172.16.88.15:57406] dst[192.168.1.235:22],
		Payload: ([]uint8) (len=64 cap=64) {
		00000000  f7 1d 1a a8 b3 2d 9d f7  c3 13 2f 59 38 a1 13 c3  |.....-..../Y8...|
		00000010  3a ab 50 d3 f9 26 80 23  bb 86 41 33 93 65 28 87  |:.P..&.#..A3.e(.|
		00000020  c8 2e 42 cf d2 2c d9 db  2b 09 f5 d9 ce e3 a8 ff  |..B..,..+.......|
		00000030  83 89 a3 9d c7 ce 6f 48  e1 62 b1 5a 3f 63 ca 08  |......oH.b.Z?c..|
		}
		})
		(*common.TCPTuple)(0xc001216438)(TcpTuple src[172.16.88.15:57406] dst[192.168.1.235:22] stream_id[1])
		(uint8) 1
		(interface {}) <nil>

		sp and conn look like the below. The fact that a bunch of these values
		in the connects are NIL seem to be normal. HTTP's look the same
		(*ssh.sshPlugin)(0xc00162dcc0)({
		 ports: (protos.PortsConfig) {
		  Ports: ([]int) (len=1 cap=1) {
		   (int) 22
		  }
		 },
		 parserConfig: (ssh.parserConfig) {
		  maxBytes: (int) 10485760
		 },
		 transConfig: (ssh.transactionConfig) {
		  transactionTimeout: (time.Duration) 10s
		 },
		 pub: (ssh.transPub) {
		  sendRequest: (bool) false,
		  sendResponse: (bool) false,
		  results: (protos.Reporter) 0x1a12810
		 }
		})
		(*ssh.connection)(0xc0013ba140)({
		 streams: ([2]*ssh.stream) (len=2 cap=2) {
		  (*ssh.stream)(<nil>),
		  (*ssh.stream)(<nil>)
		 },
		 trans: (ssh.transactions) {
		  config: (*ssh.transactionConfig)(0xc00162dce0)({
		   transactionTimeout: (time.Duration) 10s
		  }),
		  requests: (ssh.messageList) {
		   head: (*ssh.message)(<nil>),
		   tail: (*ssh.message)(<nil>)
		  },
		  responses: (ssh.messageList) {
		   head: (*ssh.message)(<nil>),
		   tail: (*ssh.message)(<nil>)
		  },
		  onTransaction: (ssh.transactionHandler) 0x122de50
		 }
		})
	*/
	conn := sp.ensureConnection(private)

	/*
			(*ssh.connection)(0xc00008c600)({
		 streams: ([2]*ssh.stream) (len=2 cap=2) {
		  (*ssh.stream)(<nil>),
		  (*ssh.stream)(<nil>)
		 },
		 trans: (ssh.transactions) {
		  config: (*ssh.transactionConfig)(0xc001593e60)({
		   transactionTimeout: (time.Duration) 10s
		  }),
		  requests: (ssh.messageList) {
		   head: (*ssh.message)(<nil>),
		   tail: (*ssh.message)(<nil>)
		  },
		  responses: (ssh.messageList) {
		   head: (*ssh.message)(<nil>),
		   tail: (*ssh.message)(<nil>)
		  },
		  onTransaction: (ssh.transactionHandler) 0xfa4310
		 }
		})

	*/

	// Printing this on HTTP gets you something like this: &{0xc0000c6598 [] 0 0 0 <nil>}
	// When there is actually data the data field blows up. It's the one with the brackets

	// This grabs all streams for the direction in which the traffic is flowing.
	st := conn.streams[dir]
	// After running: (*ssh.stream)(<nil>)

	if st == nil {
		st = &stream{} // Create a new stream if one doesn't already exist
		st.parser.init(&sp.parserConfig, func(msg *message) error {
			return conn.trans.onMessage(tcptuple.IPPort(), dir, msg)
		})
		conn.streams[dir] = st
	} else {
		//TODO This is where we should do something if the stream is already
		// being processed
		/*
			THIS IS WHAT HTTP HAS
			// concatenate bytes
			totalLength := len(st.data) + len(pkt.Payload)
			msg := st.message
			if msg != nil {
				totalLength += len(msg.body)
			}
			if totalLength > http.maxMessageSize {
				if isDebug {
					debugf("Stream data too large, ignoring message")
				}
				extraMsgSize = len(pkt.Payload)
			} else {
				st.data = append(st.data, pkt.Payload...)
			}
		*/

		global_data = new(ssh_flow_data)
		peer_data = new(ssh_peer_data)
	
		// This figures out if a conversation already exists for this. If not
		// it starts a new conversation
		// TODO NEED TO FIGURE OUT WHERE THIS SHOULD GO
		// TODO conversation = find_or_create_conversation(pinfo);
	
		global_data = (struct ssh_flow_data *)conversation_get_proto_data(conversation, proto_ssh);
		if (!global_data) {
			global_data = (struct ssh_flow_data *)wmem_alloc0(wmem_file_scope(), sizeof(struct ssh_flow_data));
			global_data->version=SSH_VERSION_UNKNOWN;
			global_data->kex_specific_dissector=ssh_dissect_kex_dh;
			global_data->peer_data[CLIENT_PEER_DATA].mac_length=-1;
			global_data->peer_data[SERVER_PEER_DATA].mac_length=-1;
	
			conversation_add_proto_data(conversation, proto_ssh, global_data);
		}
	
		peer_data = &global_data->peer_data[is_response];
	}

	/*
	   st after the above runs
	   (*ssh.stream)(0xc001184d80)({
	    parser: (ssh.parser) {
	     buf: (streambuf.Buffer) {
	      data: ([]uint8) <nil>,
	      err: (error) <nil>,
	      fixed: (bool) false,
	      mark: (int) 0,
	      offset: (int) 0,
	      available: (int) 0
	     },
	     config: (*ssh.parserConfig)(0xc001704818)({
	      maxBytes: (int) 10485760
	     }),
	     message: (*ssh.message)(<nil>),
	     onMessage: (func(*ssh.message) error) 0xfa4110
	    }
	   })
	*/

	if err := st.parser.feed(pkt.Ts, pkt.Payload); err != nil { // TODO this is where the parsing is happening
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
