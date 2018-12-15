package ssh

import (
	"fmt"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"

	"github.com/elastic/beats/packetbeat/protos"
	"github.com/elastic/beats/packetbeat/protos/tcp"
)

const(
	/* SSH Version 1 definition , from openssh ssh1.h */
	SSH1_MSG_NONE         = 0   /* no message */
	SSH1_MSG_DISCONNECT   = 1   /* cause (string) */
	SSH1_SMSG_PUBLIC_KEY  = 2   /* ck,msk,srvk,hostk */
	SSH1_CMSG_SESSION_KEY = 3   /* key (BIGNUM) */
	SSH1_CMSG_USER        = 4   /* user (string) */


	SSH_VERSION_UNKNOWN   = 0
	SSH_VERSION_1         = 1
	SSH_VERSION_2         = 2
)

type ssh_peer_data struct {
	uint   counter

	uint32 frame_version_start
	uint32 frame_version_end

	int32 frame_key_start
	int32 frame_key_end
	int frame_key_end_offset

	uint8*  kex_proposal

	/* For all subsequent proposals,
		[0] is client-to-server and [1] is server-to-client. */
	CLIENT_TO_SERVER_PROPOSAL int `0`
	SERVER_TO_CLIENT_PROPOSAL int `1`

	mac_proposals [2]*uint8
	uint8*  mac
	int    mac_length

	enc_proposals [2]*uint8
	uint8*  enc

	comp_proposals [2]*uint8
	uint8*  comp

	int    length_is_plaintext
};
	
type ssh_flow_data struct {
	guint   version;

	gchar*  kex;
	int   (*kex_specific_dissector)(uint8 msg_code, tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree);

	/* [0] is client's, [1] is server's */
	CLIENT_PEER_DATA int `0`
	SERVER_PEER_DATA int `1`
	peer_data [2]ssh_peer_data
}
	
int proto_ssh = -1;

/* Version exchange */
int hf_ssh_protocol = -1;

/* Framing */
int hf_ssh_packet_length= -1;
int hf_ssh_packet_length_encrypted= -1;
int hf_ssh_padding_length= -1;
int hf_ssh_payload= -1;
int hf_ssh_encrypted_packet= -1;
int hf_ssh_padding_string= -1;
int hf_ssh_mac_string= -1;

/* Message codes */
int hf_ssh_msg_code = -1;
int hf_ssh2_msg_code = -1;
int hf_ssh2_kex_dh_msg_code = -1;
int hf_ssh2_kex_dh_gex_msg_code = -1;
int hf_ssh2_kex_ecdh_msg_code = -1;

/* Algorithm negotiation */
int hf_ssh_cookie = -1;
int hf_ssh_kex_algorithms = -1;
int hf_ssh_server_host_key_algorithms = -1;
int hf_ssh_encryption_algorithms_client_to_server = -1;
int hf_ssh_encryption_algorithms_server_to_client = -1;
int hf_ssh_mac_algorithms_client_to_server=-1;
int hf_ssh_mac_algorithms_server_to_client=-1;
int hf_ssh_compression_algorithms_client_to_server=-1;
int hf_ssh_compression_algorithms_server_to_client=-1;
int hf_ssh_languages_client_to_server=-1;
int hf_ssh_languages_server_to_client=-1;
int hf_ssh_kex_algorithms_length= -1;
int hf_ssh_server_host_key_algorithms_length= -1;
int hf_ssh_encryption_algorithms_client_to_server_length= -1;
int hf_ssh_encryption_algorithms_server_to_client_length= -1;
int hf_ssh_mac_algorithms_client_to_server_length= -1;
int hf_ssh_mac_algorithms_server_to_client_length= -1;
int hf_ssh_compression_algorithms_client_to_server_length= -1;
int hf_ssh_compression_algorithms_server_to_client_length= -1;
int hf_ssh_languages_client_to_server_length= -1;
int hf_ssh_languages_server_to_client_length= -1;
int hf_ssh_first_kex_packet_follows = -1;
int hf_ssh_kex_reserved = -1;

/* Key exchange common elements */
int hf_ssh_hostkey_length = -1;
int hf_ssh_hostkey_type_length = -1;
int hf_ssh_hostkey_type = -1;
int hf_ssh_hostkey_data = -1;
int hf_ssh_hostkey_rsa_n = -1;
int hf_ssh_hostkey_rsa_e = -1;
int hf_ssh_hostkey_dsa_p = -1;
int hf_ssh_hostkey_dsa_q = -1;
int hf_ssh_hostkey_dsa_g = -1;
int hf_ssh_hostkey_dsa_y = -1;
int hf_ssh_hostkey_ecdsa_curve_id = -1;
int hf_ssh_hostkey_ecdsa_curve_id_length = -1;
int hf_ssh_hostkey_ecdsa_q = -1;
int hf_ssh_hostkey_ecdsa_q_length = -1;
int hf_ssh_kex_h_sig = -1;
int hf_ssh_kex_h_sig_length = -1;

/* Key exchange: Diffie-Hellman */
int hf_ssh_dh_e = -1;
int hf_ssh_dh_f = -1;

/* Key exchange: Diffie-Hellman Group Exchange */
int hf_ssh_dh_gex_min = -1;
int hf_ssh_dh_gex_nbits = -1;
int hf_ssh_dh_gex_max = -1;
int hf_ssh_dh_gex_p = -1;
int hf_ssh_dh_gex_g = -1;

/* Key exchange: Elliptic Curve Diffie-Hellman */
int hf_ssh_ecdh_q_c = -1;
int hf_ssh_ecdh_q_c_length = -1;
int hf_ssh_ecdh_q_s = -1;
int hf_ssh_ecdh_q_s_length = -1;

/* Miscellaneous */
int hf_ssh_mpint_length = -1;

int ett_ssh = -1;
int ett_key_exchange = -1;
int ett_key_exchange_host_key = -1;
int ett_key_init = -1;
int ett_ssh1 = -1;
int ett_ssh2 = -1;

expert_field ei_ssh_packet_length = EI_INIT;

gboolean ssh_desegment = TRUE;

dissector_handle_t ssh_handle;

const(
	// 29418/tcp: Gerrit Code Review
	TCP_RANGE_SSH  = "22,29418"
	SCTP_PORT_SSH = 22
	
	/* Message Numbers (from RFC 4250) (1-255) */
	
	/* Transport layer protocol: generic (1-19) */
	SSH_MSG_DISCONNECT        = 1
	SSH_MSG_IGNORE            = 2
	SSH_MSG_UNIMPLEMENTED     = 3
	SSH_MSG_DEBUG             = 4
	SSH_MSG_SERVICE_REQUEST   = 5
	SSH_MSG_SERVICE_ACCEPT    = 6
	
	/* Transport layer protocol: Algorithm negotiation (20-29) */
	SSH_MSG_KEXINIT           = 20
	SSH_MSG_NEWKEYS           = 21
	
	/* Transport layer: Key exchange method specific (reusable) (30-49) */
	SSH_MSG_KEXDH_INIT        = 30
	SSH_MSG_KEXDH_REPLY       = 31
	
	SSH_MSG_KEX_DH_GEX_REQUEST_OLD = 30
	SSH_MSG_KEX_DH_GEX_GROUP       = 31
	SSH_MSG_KEX_DH_GEX_INIT        = 32
	SSH_MSG_KEX_DH_GEX_REPLY       = 33
	SSH_MSG_KEX_DH_GEX_REQUEST     = 34
	
	SSH_MSG_KEX_ECDH_INIT     = 30
	SSH_MSG_KEX_ECDH_REPLY    = 31
	
	/* User authentication protocol: generic (50-59) */
	SSH_MSG_USERAUTH_REQUEST  = 50
	SSH_MSG_USERAUTH_FAILURE  = 51
	SSH_MSG_USERAUTH_SUCCESS  = 52
	SSH_MSG_USERAUTH_BANNER   = 53
	
	/* User authentication protocol: method specific (reusable) (50-79) */
	
	/* Connection protocol: generic (80-89) */
	SSH_MSG_GLOBAL_REQUEST        = 80
	SSH_MSG_REQUEST_SUCCESS       = 81
	SSH_MSG_REQUEST_FAILURE       = 82
	
	/* Connection protocol: channel related messages (90-127) */
	SSH_MSG_CHANNEL_OPEN              = 90
	SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91
	SSH_MSG_CHANNEL_OPEN_FAILURE      = 92
	SSH_MSG_CHANNEL_WINDOW_ADJUST     = 93
	SSH_MSG_CHANNEL_DATA              = 94
	SSH_MSG_CHANNEL_EXTENDED_DATA     = 95
	SSH_MSG_CHANNEL_EOF               = 96
	SSH_MSG_CHANNEL_CLOSE             = 97
	SSH_MSG_CHANNEL_REQUEST           = 98
	SSH_MSG_CHANNEL_SUCCESS           = 99
	SSH_MSG_CHANNEL_FAILURE           = 100

	/* 128-191 reserved for client protocols */
	/* 192-255 local extensions */
)
	
const value_string ssh2_msg_vals[] = {
	{ SSH_MSG_DISCONNECT,                "Disconnect" },
	{ SSH_MSG_IGNORE,                    "Ignore" },
	{ SSH_MSG_UNIMPLEMENTED,             "Unimplemented" },
	{ SSH_MSG_DEBUG,                     "Debug" },
	{ SSH_MSG_SERVICE_REQUEST,           "Service Request" },
	{ SSH_MSG_SERVICE_ACCEPT,            "Service Accept" },
	{ SSH_MSG_KEXINIT,                   "Key Exchange Init" },
	{ SSH_MSG_NEWKEYS,                   "New Keys" },
	{ SSH_MSG_USERAUTH_REQUEST,          "User Authentication Request" },
	{ SSH_MSG_USERAUTH_FAILURE,          "User Authentication Failure" },
	{ SSH_MSG_USERAUTH_SUCCESS,          "User Authentication Success" },
	{ SSH_MSG_USERAUTH_BANNER,           "User Authentication Banner" },
	{ SSH_MSG_GLOBAL_REQUEST,            "Global Request" },
	{ SSH_MSG_REQUEST_SUCCESS,           "Request Success" },
	{ SSH_MSG_REQUEST_FAILURE,           "Request Failure" },
	{ SSH_MSG_CHANNEL_OPEN,              "Channel Open" },
	{ SSH_MSG_CHANNEL_OPEN_CONFIRMATION, "Channel Open Confirmation" },
	{ SSH_MSG_CHANNEL_OPEN_FAILURE,      "Channel Open Failure" },
	{ SSH_MSG_CHANNEL_WINDOW_ADJUST,     "Window Adjust" },
	{ SSH_MSG_CHANNEL_DATA,              "Channel Data" },
	{ SSH_MSG_CHANNEL_EXTENDED_DATA,     "Channel Extended Data" },
	{ SSH_MSG_CHANNEL_EOF,               "Channel EOF" },
	{ SSH_MSG_CHANNEL_CLOSE,             "Channel Close" },
	{ SSH_MSG_CHANNEL_REQUEST,           "Channel Request" },
	{ SSH_MSG_CHANNEL_SUCCESS,           "Channel Success" },
	{ SSH_MSG_CHANNEL_FAILURE,           "Channel Failure" },
	{ 0, NULL }
};
	
	const value_string ssh2_kex_dh_msg_vals[] = {
		{ SSH_MSG_KEXDH_INIT,                "Diffie-Hellman Key Exchange Init" },
		{ SSH_MSG_KEXDH_REPLY,               "Diffie-Hellman Key Exchange Reply" },
		{ 0, NULL }
	};
	
	const value_string ssh2_kex_dh_gex_msg_vals[] = {
		{ SSH_MSG_KEX_DH_GEX_REQUEST_OLD,    "Diffie-Hellman Group Exchange Request (Old)" },
		{ SSH_MSG_KEX_DH_GEX_GROUP,          "Diffie-Hellman Group Exchange Group" },
		{ SSH_MSG_KEX_DH_GEX_INIT,           "Diffie-Hellman Group Exchange Init" },
		{ SSH_MSG_KEX_DH_GEX_REPLY,          "Diffie-Hellman Group Exchange Reply" },
		{ SSH_MSG_KEX_DH_GEX_REQUEST,        "Diffie-Hellman Group Exchange Request" },
		{ 0, NULL }
	};
	
	const value_string ssh2_kex_ecdh_msg_vals[] = {
		{ SSH_MSG_KEX_ECDH_INIT,             "Elliptic Curve Diffie-Hellman Key Exchange Init" },
		{ SSH_MSG_KEX_ECDH_REPLY,            "Elliptic Curve Diffie-Hellman Key Exchange Reply" },
		{ 0, NULL }
	};
	
	const value_string ssh1_msg_vals[] = {
		{SSH1_MSG_NONE,                      "No Message"},
		{SSH1_MSG_DISCONNECT,                "Disconnect"},
		{SSH1_SMSG_PUBLIC_KEY,               "Public Key"},
		{SSH1_CMSG_SESSION_KEY,              "Session Key"},
		{SSH1_CMSG_USER,                     "User"},
		{0, NULL}
	};

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
// This is called by tcp.go after the tcp header is read and deencapsulated
func (sp *sshPlugin) Parse(
	pkt *protos.Packet,
	tcptuple *common.TCPTuple,
	dir uint8,
	private protos.ProtocolData,
) protos.ProtocolData {
	//debug.PrintStack()
	defer logp.Recover("Parse sshPlugin exception")

	spew.Dump(sp, pkt, tcptuple, dir, private)
	fmt.Println("Press the Enter Key to terminate the console screen!")
	fmt.Scanln() // wait for Enter Key

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
		fmt.Println(st.parser.message)
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
