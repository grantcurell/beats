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
	"bytes"
	"errors"
	"time"

	"github.com/elastic/beats/libbeat/common/streambuf"
	"github.com/elastic/beats/packetbeat/protos/applayer"
)

type parser struct {
	buf     streambuf.Buffer
	config  *parserConfig
	message *message

	onMessage func(m *message) error

	kex *uint8

	// TODO THIS IS A POINTER TO A FUNCTION THAT I WILL NEED TO PORT
	//int   (*kex_specific_dissector)(uint8 msg_code, tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree);

	num uint32 `0`

	nodeData [2]peerData
}

type parserConfig struct {
	maxBytes int
}

type message struct {
	applayer.Message

	// indicator for parsed message being complete or requires more messages
	// (if false) to be merged to generate full message.
	isComplete bool

	info string

	isRequest bool

	// list element use by 'transactions' for correlation
	next *message
}

// Error code if stream exceeds max allowed size on append.
var (
	ErrStreamTooLarge = errors.New("Stream data too large")
)

type peerData struct {
	// SSH specific variables
	counter uint `0`

	frameVersionStart uint32 `0`
	frameVersionEnd   uint32 `0`

	frame_key_start      int32 `0`
	frame_key_end        int32 `0`
	frame_key_end_offset int   `0`

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

	sshVersion uint
}

const (
	CLIENT_PEER_DATA = 0
	SERVER_PEER_DATA = 1
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

	// TODO THIS IS A POINTER TO A FUNCTION THAT I WILL NEED TO PORT
	//global_data->kex_specific_dissector=ssh_dissect_kex_dh;
	*p = parser{
		buf:       streambuf.Buffer{},
		config:    cfg,
		onMessage: onMessage,
	}

	p.nodeData[CLIENT_PEER_DATA].sshVersion = SSH_VERSION_UNKNOWN
	p.nodeData[SERVER_PEER_DATA].sshVersion = SSH_VERSION_UNKNOWN
	p.nodeData[CLIENT_PEER_DATA] = peerData{mac_length: -1}
	p.nodeData[SERVER_PEER_DATA] = peerData{mac_length: -1}

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

func (p *parser) feed(ts time.Time, data []byte, dir uint8, isRequest bool) error {

	// EXTRA static int dissect_ssh(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)

	// EXTRA proto_tree  *ssh_tree
	// EXTRA proto_item  *ti
	// EXTRA conversation_t *conversation

	/*


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

	for p.buf.Total() > 0 {

		if p.message == nil {
			// allocate new message object to be used by parser with current timestamp
			p.message = p.newMessage(ts)
		}

		if isRequest {
			p.message.info += "Client: "
			p.message.isRequest = true
		} else {
			p.message.info += "Server: "
			p.message.isRequest = false
		}

		// This is where we actually dissect a specific message
		msg, err := p.parse(p.message, data, dir)

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
		EXAMPLE OF PUBLISHING
		fields := common.MapStr{
			"type":    "ssh",
			"version": 2,
		}
		st.pub.results(beat.Event{Timestamp: ts, Fields: fields})*/

	return nil
}

func (p *parser) newMessage(ts time.Time) *message {

	return &message{
		Message: applayer.Message{
			Ts: ts,
		},
	}
}

func (p *parser) parse(msg *message, data []byte, dir uint8) (*message, error) {

	//lastOffset := 0
	var offset uint

	// TODO I THINK I'LL BE ABLE TO GET RID OF THIS
	//needDesegmentation := false

	nodeData := p.nodeData[dir]

	// TODO NEED TO FIGURE OUT WHAT THIS NUM IS DOING
	afterVersionStart := (nodeData.frameVersionStart == 0 || p.num >= nodeData.frameVersionStart)

	beforeVersionStart := (nodeData.frameVersionEnd == 0 || p.num <= nodeData.frameVersionEnd)

	nodeData.counter++

	if afterVersionStart && beforeVersionStart && bytes.Equal([]byte("SSH-"), data[offset:4]) {

		if nodeData.frameVersionEnd == 0 {
			nodeData.frameVersionEnd = p.num
		}

		sshDissectProtocol(data, p, offset, &nodeData.sshVersion, msg)

		/* TODO NOT SURE I NEED THIS
		if !needDesegmentation {
			nodeData.frameVersionEnd = p.num
			p.version = version
		}*/
	} else {
		switch nodeData.sshVersion {
		case SSH_VERSION_UNKNOWN:
			offset = sshDissectEncryptedPacket( /*tvb, pinfo, &global_data->peer_data[is_response], offset, ssh_tree*/ )
			break
		case SSH_VERSION_1:
			offset = sshDissectSSH1( /*tvb, pinfo, global_data, offset, ssh_tree, is_response, &need_desegmentation*/ )
			break
		case SSH_VERSION_2:
			offset = sshDissectSSH2( /*tvb, pinfo, global_data, offset, ssh_tree, is_response, &need_desegmentation*/ )
			break
		}
	}

	/*
		TODO I THINK I CAN GET RID OF THIS
		if (need_desegmentation)
			return tvb_captured_length(tvb);
	*/

	/*if offset <= last_offset {
		// XXX - add an expert info in the function that decrements offset
		break
	}*/

	// TODO NEED TO MAKE SURE THIS IS COVERED APPROPRIATELY
	//return tvb_captured_length(tvb);

	// TODO need to add the error
	//return msg, errors.New("TODO: implement me")

	return msg, nil
}

// TODO I THINK I CAN GET RID OF THE NEED DESEGMENTATION
func sshDissectProtocol(data []byte, p *parser, offset uint, version *uint, msg *message /*needDesegmentation bool*/) {

	/*
	 *  If the first packet do not contain the banner,
	 *  it is dump in the middle of a flow or not a ssh at all
	 */
	if !bytes.Equal([]byte("SSH-"), data[offset:4]) {
		// TODO NEED TO COME BACK TO THIS
		sshDissectEncryptedPacket( /*tvb, pinfo, &global_data->peer_data[is_response], offset, tree*/ )
	} else {

		linelen := bytes.Index(data, []byte(string('\r')))

		if bytes.Equal([]byte("SSH-2."), data[offset:6]) {
			*version = SSH_VERSION_2
		} else if bytes.Equal([]byte("SSH-1.99-"), data[offset:9]) {
			*version = SSH_VERSION_2
		} else if bytes.Equal([]byte("SSH-1."), data[offset:6]) {
			*version = SSH_VERSION_1
		}

		msg.info += string(data[offset:linelen])
		msg.isComplete = true

		debugf("Found the start of SSH conversation. Version is %v", *version)
	}

	/*
			 * TODO NEED TO UPDATE THIS COMMENT
		     * We use "tvb_ensure_captured_length_remaining()" to make sure there
		     * actually *is* data remaining.
		     *
		     * This means we're guaranteed that "remainLength" is positive.
	*/

	/*
			TODO NEED TO COME BACK TO THIS
		    if (ssh_desegment && pinfo->can_desegment) {
		        if (linelen == -1 || remainLength < (guint)linelen-offset) {
		            pinfo->desegment_offset = offset;
		            pinfo->desegment_len = linelen-remainLength;
		            *need_desegmentation = TRUE;
		            return offset;
		        }
		    }
		    if (linelen == -1) {
		        // XXX - reassemble across segment boundaries?
		        linelen = remainLength;
		        protolen = linelen;
		    } else {
		        linelen = linelen - offset + 1;

		        if (linelen > 1 && tvb_get_guint8(tvb, offset + linelen - 2) == '\r')
		            protolen = linelen - 2;
		        else
		            protolen = linelen - 1;
			}*/

}

func sshDissectEncryptedPacket() uint {
	return 1
}

func sshDissectSSH1() uint {
	return 1
}

func sshDissectSSH2() uint {
	return 1
}
