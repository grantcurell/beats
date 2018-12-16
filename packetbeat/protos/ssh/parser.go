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

// This file is used to parse the inbound data received by packetbeat

package ssh

import (
	"errors"
	"os"
	"time"

	"github.com/davecgh/go-spew/spew"

	"github.com/elastic/beats/libbeat/common/streambuf"
	"github.com/elastic/beats/packetbeat/protos/applayer"
)

type parser struct {
	buf     streambuf.Buffer
	config  *parserConfig
	message *message

	global_data ssh_flow_data
	peer_data   ssh_peer_data

	onMessage func(m *message) error

	// SSH specific variables
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

type parserConfig struct {
	maxBytes int
}

type message struct {
	applayer.Message

	// indicator for parsed message being complete or requires more messages
	// (if false) to be merged to generate full message.
	isComplete bool

	// list element use by 'transactions' for correlation
	next *message
}

// Error code if stream exceeds max allowed size on append.
var (
	ErrStreamTooLarge = errors.New("Stream data too large")
)

const (
	/* SSH Version 1 definition , from openssh ssh1.h */
	SSH1_MSG_NONE         = 0 /* no message */
	SSH1_MSG_DISCONNECT   = 1 /* cause (string) */
	SSH1_SMSG_PUBLIC_KEY  = 2 /* ck,msk,srvk,hostk */
	SSH1_CMSG_SESSION_KEY = 3 /* key (BIGNUM) */
	SSH1_CMSG_USER        = 4 /* user (string) */

	SSH_VERSION_UNKNOWN = 0
	SSH_VERSION_1       = 1
	SSH_VERSION_2       = 2
)

var proto_ssh = -1

/* Version exchange */
var hf_ssh_protocol = -1

/* Framing */
var hf_ssh_packet_length = -1
var hf_ssh_packet_length_encrypted = -1
var hf_ssh_padding_length = -1
var hf_ssh_payload = -1
var hf_ssh_encrypted_packet = -1
var hf_ssh_padding_string = -1
var hf_ssh_mac_string = -1

/* Message codes */
var hf_ssh_msg_code = -1
var hf_ssh2_msg_code = -1
var hf_ssh2_kex_dh_msg_code = -1
var hf_ssh2_kex_dh_gex_msg_code = -1
var hf_ssh2_kex_ecdh_msg_code = -1

/* Algorithm negotiation */
var hf_ssh_cookie = -1
var hf_ssh_kex_algorithms = -1
var hf_ssh_server_host_key_algorithms = -1
var hf_ssh_encryption_algorithms_client_to_server = -1
var hf_ssh_encryption_algorithms_server_to_client = -1
var hf_ssh_mac_algorithms_client_to_server = -1
var hf_ssh_mac_algorithms_server_to_client = -1
var hf_ssh_compression_algorithms_client_to_server = -1
var hf_ssh_compression_algorithms_server_to_client = -1
var hf_ssh_languages_client_to_server = -1
var hf_ssh_languages_server_to_client = -1
var hf_ssh_kex_algorithms_length = -1
var hf_ssh_server_host_key_algorithms_length = -1
var hf_ssh_encryption_algorithms_client_to_server_length = -1
var hf_ssh_encryption_algorithms_server_to_client_length = -1
var hf_ssh_mac_algorithms_client_to_server_length = -1
var hf_ssh_mac_algorithms_server_to_client_length = -1
var hf_ssh_compression_algorithms_client_to_server_length = -1
var hf_ssh_compression_algorithms_server_to_client_length = -1
var hf_ssh_languages_client_to_server_length = -1
var hf_ssh_languages_server_to_client_length = -1
var hf_ssh_first_kex_packet_follows = -1
var hf_ssh_kex_reserved = -1

/* Key exchange common elements */
var hf_ssh_hostkey_length = -1
var hf_ssh_hostkey_type_length = -1
var hf_ssh_hostkey_type = -1
var hf_ssh_hostkey_data = -1
var hf_ssh_hostkey_rsa_n = -1
var hf_ssh_hostkey_rsa_e = -1
var hf_ssh_hostkey_dsa_p = -1
var hf_ssh_hostkey_dsa_q = -1
var hf_ssh_hostkey_dsa_g = -1
var hf_ssh_hostkey_dsa_y = -1
var hf_ssh_hostkey_ecdsa_curve_id = -1
var hf_ssh_hostkey_ecdsa_curve_id_length = -1
var hf_ssh_hostkey_ecdsa_q = -1
var hf_ssh_hostkey_ecdsa_q_length = -1
var hf_ssh_kex_h_sig = -1
var hf_ssh_kex_h_sig_length = -1

/* Key exchange: Diffie-Hellman */
var hf_ssh_dh_e = -1
var hf_ssh_dh_f = -1

/* Key exchange: Diffie-Hellman Group Exchange */
var hf_ssh_dh_gex_min = -1
var hf_ssh_dh_gex_nbits = -1
var hf_ssh_dh_gex_max = -1
var hf_ssh_dh_gex_p = -1
var hf_ssh_dh_gex_g = -1

/* Key exchange: Elliptic Curve Diffie-Hellman */
var hf_ssh_ecdh_q_c = -1
var hf_ssh_ecdh_q_c_length = -1
var hf_ssh_ecdh_q_s = -1
var hf_ssh_ecdh_q_s_length = -1

/* Miscellaneous */
var hf_ssh_mpint_length = -1

var ett_ssh = -1
var ett_key_exchange = -1
var ett_key_exchange_host_key = -1
var ett_key_init = -1
var ett_ssh1 = -1
var ett_ssh2 = -1

// TODO expert_field ei_ssh_packet_length = EI_INIT;

var ssh_desegment = true

// TODO dissector_handle_t ssh_handle;

const (
	// 29418/tcp: Gerrit Code Review
	TCP_RANGE_SSH = "22,29418"
	SCTP_PORT_SSH = 22

	/* Message Numbers (from RFC 4250) (1-255) */

	/* Transport layer protocol: generic (1-19) */
	SSH_MSG_DISCONNECT      = 1
	SSH_MSG_IGNORE          = 2
	SSH_MSG_UNIMPLEMENTED   = 3
	SSH_MSG_DEBUG           = 4
	SSH_MSG_SERVICE_REQUEST = 5
	SSH_MSG_SERVICE_ACCEPT  = 6

	/* Transport layer protocol: Algorithm negotiation (20-29) */
	SSH_MSG_KEXINIT = 20
	SSH_MSG_NEWKEYS = 21

	/* Transport layer: Key exchange method specific (reusable) (30-49) */
	SSH_MSG_KEXDH_INIT  = 30
	SSH_MSG_KEXDH_REPLY = 31

	SSH_MSG_KEX_DH_GEX_REQUEST_OLD = 30
	SSH_MSG_KEX_DH_GEX_GROUP       = 31
	SSH_MSG_KEX_DH_GEX_INIT        = 32
	SSH_MSG_KEX_DH_GEX_REPLY       = 33
	SSH_MSG_KEX_DH_GEX_REQUEST     = 34

	SSH_MSG_KEX_ECDH_INIT  = 30
	SSH_MSG_KEX_ECDH_REPLY = 31

	/* User authentication protocol: generic (50-59) */
	SSH_MSG_USERAUTH_REQUEST = 50
	SSH_MSG_USERAUTH_FAILURE = 51
	SSH_MSG_USERAUTH_SUCCESS = 52
	SSH_MSG_USERAUTH_BANNER  = 53

	/* User authentication protocol: method specific (reusable) (50-79) */

	/* Connection protocol: generic (80-89) */
	SSH_MSG_GLOBAL_REQUEST  = 80
	SSH_MSG_REQUEST_SUCCESS = 81
	SSH_MSG_REQUEST_FAILURE = 82

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

type value_string struct {
	value  uint32
	strptr string
}

var ssh2_msg_vals = []value_string{
	{SSH_MSG_DISCONNECT, "Disconnect"},
	{SSH_MSG_IGNORE, "Ignore"},
	{SSH_MSG_UNIMPLEMENTED, "Unimplemented"},
	{SSH_MSG_DEBUG, "Debug"},
	{SSH_MSG_SERVICE_REQUEST, "Service Request"},
	{SSH_MSG_SERVICE_ACCEPT, "Service Accept"},
	{SSH_MSG_KEXINIT, "Key Exchange Init"},
	{SSH_MSG_NEWKEYS, "New Keys"},
	{SSH_MSG_USERAUTH_REQUEST, "User Authentication Request"},
	{SSH_MSG_USERAUTH_FAILURE, "User Authentication Failure"},
	{SSH_MSG_USERAUTH_SUCCESS, "User Authentication Success"},
	{SSH_MSG_USERAUTH_BANNER, "User Authentication Banner"},
	{SSH_MSG_GLOBAL_REQUEST, "Global Request"},
	{SSH_MSG_REQUEST_SUCCESS, "Request Success"},
	{SSH_MSG_REQUEST_FAILURE, "Request Failure"},
	{SSH_MSG_CHANNEL_OPEN, "Channel Open"},
	{SSH_MSG_CHANNEL_OPEN_CONFIRMATION, "Channel Open Confirmation"},
	{SSH_MSG_CHANNEL_OPEN_FAILURE, "Channel Open Failure"},
	{SSH_MSG_CHANNEL_WINDOW_ADJUST, "Window Adjust"},
	{SSH_MSG_CHANNEL_DATA, "Channel Data"},
	{SSH_MSG_CHANNEL_EXTENDED_DATA, "Channel Extended Data"},
	{SSH_MSG_CHANNEL_EOF, "Channel EOF"},
	{SSH_MSG_CHANNEL_CLOSE, "Channel Close"},
	{SSH_MSG_CHANNEL_REQUEST, "Channel Request"},
	{SSH_MSG_CHANNEL_SUCCESS, "Channel Success"},
	{SSH_MSG_CHANNEL_FAILURE, "Channel Failure"},
	{0, ""},
}

var ssh2_kex_dh_msg_vals = []value_string{
	{SSH_MSG_KEXDH_INIT, "Diffie-Hellman Key Exchange Init"},
	{SSH_MSG_KEXDH_REPLY, "Diffie-Hellman Key Exchange Reply"},
	{0, ""},
}

var ssh2_kex_dh_gex_msg_vals = []value_string{
	{SSH_MSG_KEX_DH_GEX_REQUEST_OLD, "Diffie-Hellman Group Exchange Request (Old)"},
	{SSH_MSG_KEX_DH_GEX_GROUP, "Diffie-Hellman Group Exchange Group"},
	{SSH_MSG_KEX_DH_GEX_INIT, "Diffie-Hellman Group Exchange Init"},
	{SSH_MSG_KEX_DH_GEX_REPLY, "Diffie-Hellman Group Exchange Reply"},
	{SSH_MSG_KEX_DH_GEX_REQUEST, "Diffie-Hellman Group Exchange Request"},
	{0, ""},
}

var ssh2_kex_ecdh_msg_vals = []value_string{
	{SSH_MSG_KEX_ECDH_INIT, "Elliptic Curve Diffie-Hellman Key Exchange Init"},
	{SSH_MSG_KEX_ECDH_REPLY, "Elliptic Curve Diffie-Hellman Key Exchange Reply"},
	{0, ""},
}

var ssh1_msg_vals = []value_string{
	{SSH1_MSG_NONE, "No Message"},
	{SSH1_MSG_DISCONNECT, "Disconnect"},
	{SSH1_SMSG_PUBLIC_KEY, "Public Key"},
	{SSH1_CMSG_SESSION_KEY, "Session Key"},
	{SSH1_CMSG_USER, "User"},
	{0, ""},
}

func (p *parser) init(
	cfg *parserConfig,
	onMessage func(*message) error,
) {

	*p = parser{
		buf:        streambuf.Buffer{},
		config:     cfg,
		onMessage:  onMessage,
		mac_length: -1,
	}
}

func (p *parser) append(data []byte) error {
	_, err := p.buf.Write(data)
	if err != nil {
		return err
	}

	if p.config.maxBytes > 0 && p.buf.Total() > p.config.maxBytes {
		return ErrStreamTooLarge
	}
	return nil
}

func (p *parser) feed(ts time.Time, data []byte) error {

	// EXTRA static int dissect_ssh(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)

	// EXTRA proto_tree  *ssh_tree
	// EXTRA proto_item  *ti
	// EXTRA conversation_t *conversation

	var int last_offset
	offset := 0

	// Determine if the indbound data is a response or not
	// EXTRA NEED TO DETERMINE IF THIS IS A RESPONSE OR NOT
	// var bool is_response = (pinfo->destport != pinfo->match_uint),
	// EXTRA
	// peer_data = &global_data->peer_data[is_response];
	// EXTRA NOT SURE IF WE'LL NEED THIS
	// need_desegmentation;

	// EXTRA NOT SURE IF I NEED TO DO ANYTHING WITH THESE
	//ti = proto_tree_add_item(tree, proto_ssh, tvb, offset, -1, ENC_NA);
	//ssh_tree = proto_item_add_subtree(ti, ett_ssh);

	/*
		EXTRA I CAN PROBABLY GET RID OF THIS BLOCK. I DON'T HAVE A COLUMN TO SET
		IT JUST NEEDS TO BE SET IN THE FIELDS
		version = global_data->version;

		switch(version) {
		case SSH_VERSION_UNKNOWN:
			col_set_str(pinfo->cinfo, COL_PROTOCOL, "SSH");
			break;
		case SSH_VERSION_1:
			col_set_str(pinfo->cinfo, COL_PROTOCOL, "SSHv1");
			break;
		case SSH_VERSION_2:
			col_set_str(pinfo->cinfo, COL_PROTOCOL, "SSHv2");
			break;

		}

		col_clear(pinfo->cinfo, COL_INFO);
	*/

	if err := p.append(data); err != nil {
		return err
	}

	spew.Dump(p)
	os.Exit(3)
	for p.buf.Total() > 0 {
		if p.message == nil {
			// allocate new message object to be used by parser with current timestamp
			p.message = p.newMessage(ts)
		}

		msg, err := p.parse()
		if err != nil {
			return err
		}
		if msg == nil {
			break // wait for more data
		}

		// reset buffer and message -> handle next message in buffer
		p.buf.Reset()
		p.message = nil

		// call message handler callback
		if err := p.onMessage(msg); err != nil {
			return err
		}
	}

	/*
		while(tvb_reported_length_remaining(tvb, offset)> 0) {
			gboolean after_version_start = (peer_data->frame_version_start == 0 ||
			pinfo->num >= peer_data->frame_version_start);
			gboolean before_version_end = (peer_data->frame_version_end == 0 ||
			pinfo->num <= peer_data->frame_version_end);

			need_desegmentation = FALSE;
			last_offset = offset;

			peer_data->counter++;

			if (after_version_start && before_version_end &&
			(tvb_strncaseeql(tvb, offset, "SSH-", 4) == 0)) {
			if (peer_data->frame_version_start == 0)
				peer_data->frame_version_start = pinfo->num;

			offset = ssh_dissect_protocol(tvb, pinfo,
				global_data,
				offset, ssh_tree, is_response,
				&version, &need_desegmentation);

			if (!need_desegmentation) {
				peer_data->frame_version_end = pinfo->num;
				global_data->version = version;
			}
			} else {
			switch(version) {

			case SSH_VERSION_UNKNOWN:
				offset = ssh_dissect_encrypted_packet(tvb, pinfo,
					&global_data->peer_data[is_response], offset, ssh_tree);
				break;

			case SSH_VERSION_1:
				offset = ssh_dissect_ssh1(tvb, pinfo, global_data,
					offset, ssh_tree, is_response,
					&need_desegmentation);
				break;

			case SSH_VERSION_2:
				offset = ssh_dissect_ssh2(tvb, pinfo, global_data,
					offset, ssh_tree, is_response,
					&need_desegmentation);
				break;
			}
			}

			if (need_desegmentation)
			return tvb_captured_length(tvb);
			if (offset <= last_offset) {
			// XXX - add an expert info in the function that decrements offset
		break;
			}
		}

		col_prepend_fstr(pinfo->cinfo, COL_INFO, "%s: ", is_response ? "Server" : "Client");
		return tvb_captured_length(tvb);*/

	return nil
}

// Your protocol will begin parsing here. This is where you should start
func (p *parser) newMessage(ts time.Time) *message {

	return &message{
		Message: applayer.Message{
			Ts: ts,
		},
	}
}

// This function could be anything. In the other examples it's completely different with different
// arguments each time
func (p *parser) parse() (*message, error) {
	/*
		Message looks like this
		(*ssh.message)(0xc0019b8a50)({
		 Message: (applayer.Message) {
		  Ts: (time.Time) 2018-12-15 12:53:33.522029 -0600 CST,
		  Tuple: (common.IPPortTuple) IpPortTuple src[<nil>:0] dst[<nil>:0],
		  Transport: (applayer.Transport) udp,
		  CmdlineTuple: (*common.CmdlineTuple)(<nil>),
		  Direction: (applayer.NetDirection) 0,
		  IsRequest: (bool) false,
		  Size: (uint64) 0,
		  Notes: ([]string) <nil>
		 },
		 isComplete: (bool) false,
		 next: (*ssh.message)(<nil>)
		})

		goroutine 131 [running]:
		runtime/debug.Stack(0x0, 0x50, 0xc00162dac8)
			/usr/local/go/src/runtime/debug/stack.go:24 +0xa7
		runtime/debug.PrintStack()
			/usr/local/go/src/runtime/debug/stack.go:16 +0x22
		github.com/elastic/beats/packetbeat/protos/ssh.(*parser).parse(0xc0012c0420, 0xc000a46000, 0x40, 0x40)
			/root/go/src/github.com/elastic/beats/packetbeat/protos/ssh/parser.go:129 +0x26
		github.com/elastic/beats/packetbeat/protos/ssh.(*parser).feed(0xc0012c0420, 0x25b9d258, 0xed3a60882, 0x25438e0, 0xc0016b40b8, 0x40, 0x40, 0xc00162db76, 0xc00160c518)
			/root/go/src/github.com/elastic/beats/packetbeat/protos/ssh/parser.go:95 +0x8d
		github.com/elastic/beats/packetbeat/protos/ssh.(*sshPlugin).Parse(0xc0015d3b80, 0xc0009be000, 0xc0011a60c8, 0xc0015d3b01, 0x0, 0x0, 0x0, 0x0)
			/root/go/src/github.com/elastic/beats/packetbeat/protos/ssh/ssh.go:236 +0x175
		github.com/elastic/beats/packetbeat/protos/tcp.(*TCPStream).addPacket(0xc00162dcb0, 0xc0009be000, 0xc00111b2a0)
			/root/go/src/github.com/elastic/beats/packetbeat/protos/tcp/tcp.go:145 +0x159
		github.com/elastic/beats/packetbeat/protos/tcp.(*TCP).Process(0xc0016d42d0, 0xc0015087c0, 0xc00111b2a0, 0xc0009be000)
			/root/go/src/github.com/elastic/beats/packetbeat/protos/tcp/tcp.go:240 +0x327
		github.com/elastic/beats/packetbeat/decoder.(*Decoder).onTCP(0xc00111ad00, 0xc0009be000)
			/root/go/src/github.com/elastic/beats/packetbeat/decoder/decoder.go:334 +0xdd
		github.com/elastic/beats/packetbeat/decoder.(*Decoder).process(0xc00111ad00, 0xc0009be000, 0x2c, 0x40, 0x193f160, 0xc00111ad00)
			/root/go/src/github.com/elastic/beats/packetbeat/decoder/decoder.go:275 +0x1dd
		github.com/elastic/beats/packetbeat/decoder.(*Decoder).OnPacket(0xc00111ad00, 0xc0016b40b8, 0x40, 0x40, 0xc001163500)
			/root/go/src/github.com/elastic/beats/packetbeat/decoder/decoder.go:181 +0x317
		github.com/elastic/beats/packetbeat/sniffer.(*Sniffer).Run(0xc0015d4b00, 0x0, 0x0)
			/root/go/src/github.com/elastic/beats/packetbeat/sniffer/sniffer.go:210 +0x466
		github.com/elastic/beats/packetbeat/beater.(*packetbeat).Run.func2(0xc001164720, 0xc0015fc000, 0xc001636b40)
			/root/go/src/github.com/elastic/beats/packetbeat/beater/packetbeat.go:225 +0x60
		created by github.com/elastic/beats/packetbeat/beater.(*packetbeat).Run
				/root/go/src/github.com/elastic/beats/packetbeat/beater/packetbeat.go:222 +0x129
	*/

	// Need to check the parser state. There's some parser object that's getting
	// passed around. In HTTP it's line 41 of http.go and it's just a short.
	return nil, errors.New("TODO: implement me")
}
