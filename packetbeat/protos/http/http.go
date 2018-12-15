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

package http

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/libbeat/monitoring"

	"github.com/elastic/beats/packetbeat/procs"
	"github.com/elastic/beats/packetbeat/protos"
)

var debugf = logp.MakeDebug("http")
var detailedf = logp.MakeDebug("httpdetailed")

type parserState uint8

const (
	stateStart parserState = iota
	stateHeaders
	stateBody
	stateBodyChunkedStart
	stateBodyChunked
	stateBodyChunkedWaitFinalCRLF
)

var (
	unmatchedResponses = monitoring.NewInt(nil, "http.unmatched_responses")
	unmatchedRequests  = monitoring.NewInt(nil, "http.unmatched_requests")
)

type stream struct {
	tcptuple *common.TCPTuple

	data []byte

	parseOffset  int
	parseState   parserState
	bodyReceived int

	message *message
}

type httpConnectionData struct {
	streams   [2]*stream
	requests  messageList
	responses messageList
}

type messageList struct {
	head, tail *message
}

// HTTP application level protocol analyser plugin.
type httpPlugin struct {
	// config
	ports               []int
	sendRequest         bool
	sendResponse        bool
	splitCookie         bool
	hideKeywords        []string
	redactAuthorization bool
	maxMessageSize      int
	mustDecodeBody      bool

	parserConfig parserConfig

	transactionTimeout time.Duration

	results protos.Reporter
}

var (
	isDebug    = false
	isDetailed = false
)

func init() {
	protos.Register("http", New)
}

func New(
	testMode bool,
	results protos.Reporter,
	cfg *common.Config,
) (protos.Plugin, error) {
	p := &httpPlugin{}
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

// Init initializes the HTTP protocol analyser.
func (http *httpPlugin) init(results protos.Reporter, config *httpConfig) error {
	http.setFromConfig(config)

	isDebug = logp.IsDebug("http")
	isDetailed = logp.IsDebug("httpdetailed")
	http.results = results
	return nil
}

func (http *httpPlugin) setFromConfig(config *httpConfig) {
	http.ports = config.Ports
	http.sendRequest = config.SendRequest
	http.sendResponse = config.SendResponse
	http.hideKeywords = config.HideKeywords
	http.redactAuthorization = config.RedactAuthorization
	http.splitCookie = config.SplitCookie
	http.parserConfig.realIPHeader = strings.ToLower(config.RealIPHeader)
	http.transactionTimeout = config.TransactionTimeout
	http.mustDecodeBody = config.DecodeBody

	for _, list := range [][]string{config.IncludeBodyFor, config.IncludeRequestBodyFor} {
		http.parserConfig.includeRequestBodyFor = append(http.parserConfig.includeRequestBodyFor, list...)
	}
	for _, list := range [][]string{config.IncludeBodyFor, config.IncludeResponseBodyFor} {
		http.parserConfig.includeResponseBodyFor = append(http.parserConfig.includeResponseBodyFor, list...)
	}
	http.maxMessageSize = config.MaxMessageSize

	if config.SendAllHeaders {
		http.parserConfig.sendHeaders = true
		http.parserConfig.sendAllHeaders = true
	} else {
		if len(config.SendHeaders) > 0 {
			http.parserConfig.sendHeaders = true

			http.parserConfig.headersWhitelist = map[string]bool{}
			for _, hdr := range config.SendHeaders {
				http.parserConfig.headersWhitelist[strings.ToLower(hdr)] = true
			}
		}
	}
}

// GetPorts lists the port numbers the HTTP protocol analyser will handle.
func (http *httpPlugin) GetPorts() []int {
	return http.ports
}

// messageGap is called when a gap of size `nbytes` is found in the
// tcp stream. Decides if we can ignore the gap or it's a parser error
// and we need to drop the stream.
func (http *httpPlugin) messageGap(s *stream, nbytes int) (ok bool, complete bool) {
	m := s.message
	switch s.parseState {
	case stateStart, stateHeaders:
		// we know we cannot recover from these
		return false, false
	case stateBody:
		if isDebug {
			debugf("gap in body: %d", nbytes)
		}

		if m.isRequest {
			m.notes = append(m.notes, "Packet loss while capturing the request")
		} else {
			m.notes = append(m.notes, "Packet loss while capturing the response")
		}
		if !m.hasContentLength && (bytes.Equal(m.connection, constClose) ||
			(isVersion(m.version, 1, 0) && !bytes.Equal(m.connection, constKeepAlive))) {
			s.bodyReceived += nbytes
			m.contentLength += nbytes
			return true, false
		} else if len(s.data)+nbytes >= m.contentLength-s.bodyReceived {
			// we're done, but the last portion of the data is gone
			return true, true
		} else {
			s.bodyReceived += nbytes
			return true, false
		}
	}
	// assume we cannot recover
	return false, false
}

func (st *stream) PrepareForNewMessage() {
	st.parseState = stateStart
	st.parseOffset = 0
	st.bodyReceived = 0
	st.message = nil
}

// Called when the parser has identified the boundary
// of a message.
func (http *httpPlugin) messageComplete(
	conn *httpConnectionData,
	tcptuple *common.TCPTuple,
	dir uint8,
	st *stream,
) {
	http.handleHTTP(conn, st.message, tcptuple, dir)
}

// ConnectionTimeout returns the configured HTTP transaction timeout.
func (http *httpPlugin) ConnectionTimeout() time.Duration {
	return http.transactionTimeout
}

// Parse function is used to process TCP payloads.
func (http *httpPlugin) Parse(
	pkt *protos.Packet,
	tcptuple *common.TCPTuple,
	dir uint8,
	private protos.ProtocolData,
) protos.ProtocolData {
	defer logp.Recover("ParseHttp exception")

	/*
		Call stack
			goroutine 86 [running]:
		runtime/debug.Stack(0x0, 0xc001646700, 0x203000)
		        /usr/local/go/src/runtime/debug/stack.go:24 +0xa7
		runtime/debug.PrintStack()
		        /usr/local/go/src/runtime/debug/stack.go:16 +0x22
		github.com/elastic/beats/packetbeat/protos/http.(*parser).parse(0xc0016e1b70, 0xc001370e40, 0x0, 0xc001646700)
		        /root/go/src/github.com/elastic/beats/packetbeat/protos/http/http_parser.go:120 +0x34
		github.com/elastic/beats/packetbeat/protos/http.(*httpPlugin).doParse(0xc00003b8c0, 0xc0024300f0, 0xc002414b40, 0xc0016c4388, 0x7f38aa624101, 0xc00003b8c0)
		        /root/go/src/github.com/elastic/beats/packetbeat/protos/http/http.go:319 +0x190
		github.com/elastic/beats/packetbeat/protos/http.(*httpPlugin).Parse(0xc00003b8c0, 0xc002414b40, 0xc0016c4388, 0xc00003b801, 0x0, 0x0, 0x0, 0x0)
		        /root/go/src/github.com/elastic/beats/packetbeat/protos/http/http.go:244 +0xab
		github.com/elastic/beats/packetbeat/protos/tcp.(*TCPStream).addPacket(0xc0016e1cb0, 0xc002414b40, 0xc0017345a0)
		        /root/go/src/github.com/elastic/beats/packetbeat/protos/tcp/tcp.go:145 +0x159
		github.com/elastic/beats/packetbeat/protos/tcp.(*TCP).Process(0xc0011d0550, 0xc001220a80, 0xc0017345a0, 0xc002414b40)
		        /root/go/src/github.com/elastic/beats/packetbeat/protos/tcp/tcp.go:240 +0x327
		github.com/elastic/beats/packetbeat/decoder.(*Decoder).onTCP(0xc001734000, 0xc002414b40)
		        /root/go/src/github.com/elastic/beats/packetbeat/decoder/decoder.go:334 +0xdd
		github.com/elastic/beats/packetbeat/decoder.(*Decoder).process(0xc001734000, 0xc002414b40, 0x2c, 0x263, 0x193ef60, 0xc001734000)
		        /root/go/src/github.com/elastic/beats/packetbeat/decoder/decoder.go:275 +0x1dd
		github.com/elastic/beats/packetbeat/decoder.(*Decoder).OnPacket(0xc001734000, 0xc001299904, 0x263, 0x263, 0xc0024300c0)
		        /root/go/src/github.com/elastic/beats/packetbeat/decoder/decoder.go:181 +0x317
		github.com/elastic/beats/packetbeat/sniffer.(*Sniffer).Run(0xc0016c4000, 0x0, 0x0)
		        /root/go/src/github.com/elastic/beats/packetbeat/sniffer/sniffer.go:210 +0x466
		github.com/elastic/beats/packetbeat/beater.(*packetbeat).Run.func2(0xc0011720a0, 0xc0011a9e00, 0xc0011d3740)
		        /root/go/src/github.com/elastic/beats/packetbeat/beater/packetbeat.go:225 +0x60
		created by github.com/elastic/beats/packetbeat/beater.(*packetbeat).Run
		        /root/go/src/github.com/elastic/beats/packetbeat/beater/packetbeat.go:222 +0x129
	*/
	conn := ensureHTTPConnection(private)
	conn = http.doParse(conn, pkt, tcptuple, dir)
	/*
			This is what conn looks like after parsing
		   (*http.httpConnectionData)(0xc001586f30)({
		    streams: ([2]*http.stream) (len=2 cap=2) {
		     (*http.stream)(<nil>),
		     (*http.stream)(0xc0011f2c80)({
		      tcptuple: (*common.TCPTuple)(0xc001418388)(TcpTuple src[192.168.1.235:43036] dst[216.21.170.179:80] stream_id[13]),
		      data: ([]uint8) {
		      },
		      parseOffset: (int) 0,
		      parseState: (http.parserState) 0,
		      bodyReceived: (int) 0,
		      message: (*http.message)(<nil>)
		     })
		    },
		    requests: (http.messageList) {
		     head: (*http.message)(0xc000cdc400)({
		      ts: (time.Time) 2018-12-14 13:55:45.333947 -0600 CST,
		      hasContentLength: (bool) true,
		      headerOffset: (int) 17,
		      version: (http.version) {
		       major: (uint8) 1,
		       minor: (uint8) 1
		      },
		      connection: (common.NetString) (len=10 cap=99) {
		       00000000  6b 65 65 70 2d 61 6c 69  76 65                    |keep-alive|
		      },
		      chunkedLength: (int) 0,
		      isRequest: (bool) true,
		      tcpTuple: (common.TCPTuple) TcpTuple src[192.168.1.235:43036] dst[216.21.170.179:80] stream_id[13],
		      cmdlineTuple: (*common.CmdlineTuple)(0xc0012862a0)({
		       Src: ([]uint8) <nil>,
		       Dst: ([]uint8) <nil>,
		       SrcCommand: ([]uint8) <nil>,
		       DstCommand: ([]uint8) <nil>
		      }),
		      direction: (uint8) 1,
		      requestURI: (common.NetString) (len=1 cap=446) {
		       00000000  2f                                                |/|
		      },
		      method: (common.NetString) (len=4 cap=451) {
		       00000000  50 4f 53 54                                       |POST|
		      },
		      statusCode: (uint16) 0,
		      statusPhrase: (common.NetString) <nil>,
		      realIP: (common.NetString) <nil>,
		      contentLength: (int) 85,
		      contentType: (common.NetString) (len=24 cap=157) {
		       00000000  61 70 70 6c 69 63 61 74  69 6f 6e 2f 6f 63 73 70  |application/ocsp|
		       00000010  2d 72 65 71 75 65 73 74                           |-request|
		      },
		      encodings: ([]string) <nil>,
		      isChunked: (bool) false,
		      headers: (map[string]common.NetString) {
		      },
		      size: (uint64) 451,
		      rawHeaders: ([]uint8) (len=366 cap=451) {
		       00000000  50 4f 53 54 20 2f 20 48  54 54 50 2f 31 2e 31 0d  |POST / HTTP/1.1.|
		       00000010  0a 48 6f 73 74 3a 20 6f  63 73 70 2e 69 6e 74 2d  |.Host: ocsp.int-|
		       00000020  78 33 2e 6c 65 74 73 65  6e 63 72 79 70 74 2e 6f  |x3.letsencrypt.o|
		       00000030  72 67 0d 0a 55 73 65 72  2d 41 67 65 6e 74 3a 20  |rg..User-Agent: |
		       00000040  4d 6f 7a 69 6c 6c 61 2f  35 2e 30 20 28 58 31 31  |Mozilla/5.0 (X11|
		       00000050  3b 20 46 65 64 6f 72 61  3b 20 4c 69 6e 75 78 20  |; Fedora; Linux |
		       00000060  78 38 36 5f 36 34 3b 20  72 76 3a 36 33 2e 30 29  |x86_64; rv:63.0)|
		       00000070  20 47 65 63 6b 6f 2f 32  30 31 30 30 31 30 31 20  | Gecko/20100101 |
		       00000080  46 69 72 65 66 6f 78 2f  36 33 2e 30 0d 0a 41 63  |Firefox/63.0..Ac|
		       00000090  63 65 70 74 3a 20 74 65  78 74 2f 68 74 6d 6c 2c  |cept: text/html,|
		       000000a0  61 70 70 6c 69 63 61 74  69 6f 6e 2f 78 68 74 6d  |application/xhtm|
		       000000b0  6c 2b 78 6d 6c 2c 61 70  70 6c 69 63 61 74 69 6f  |l+xml,applicatio|
		       000000c0  6e 2f 78 6d 6c 3b 71 3d  30 2e 39 2c 2a 2f 2a 3b  |n/xml;q=0.9, / ;|
		       000000d0  71 3d 30 2e 38 0d 0a 41  63 63 65 70 74 2d 4c 61  |q=0.8..Accept-La|
		       000000e0  6e 67 75 61 67 65 3a 20  65 6e 2d 55 53 2c 65 6e  |nguage: en-US,en|
		       000000f0  3b 71 3d 30 2e 35 0d 0a  41 63 63 65 70 74 2d 45  |;q=0.5..Accept-E|
		       00000100  6e 63 6f 64 69 6e 67 3a  20 67 7a 69 70 2c 20 64  |ncoding: gzip, d|
		       00000110  65 66 6c 61 74 65 0d 0a  43 6f 6e 74 65 6e 74 2d  |eflate..Content-|
		       00000120  54 79 70 65 3a 20 61 70  70 6c 69 63 61 74 69 6f  |Type: applicatio|
		       00000130  6e 2f 6f 63 73 70 2d 72  65 71 75 65 73 74 0d 0a  |n/ocsp-request..|
		       00000140  43 6f 6e 74 65 6e 74 2d  4c 65 6e 67 74 68 3a 20  |Content-Length: |
		       00000150  38 35 0d 0a 43 6f 6e 6e  65 63 74 69 6f 6e 3a 20  |85..Connection: |
		       00000160  6b 65 65 70 2d 61 6c 69  76 65 0d 0a 0d 0a        |keep-alive....|
		      },
		      sendBody: (bool) false,
		      saveBody: (bool) false,
		      body: ([]uint8) <nil>,
		      notes: ([]string) <nil>,
		      next: (*http.message)(<nil>)
		     }),
		     tail: (*http.message)(0xc000cdc400)({
		      ts: (time.Time) 2018-12-14 13:55:45.333947 -0600 CST,
		      hasContentLength: (bool) true,
		      headerOffset: (int) 17,
		      version: (http.version) {
		       major: (uint8) 1,
		       minor: (uint8) 1
		      },
		      connection: (common.NetString) (len=10 cap=99) {
		       00000000  6b 65 65 70 2d 61 6c 69  76 65                    |keep-alive|
		      },
		      chunkedLength: (int) 0,
		      isRequest: (bool) true,
		      tcpTuple: (common.TCPTuple) TcpTuple src[192.168.1.235:43036] dst[216.21.170.179:80] stream_id[13],
		      cmdlineTuple: (*common.CmdlineTuple)(0xc0012862a0)({
		       Src: ([]uint8) <nil>,
		       Dst: ([]uint8) <nil>,
		       SrcCommand: ([]uint8) <nil>,
		       DstCommand: ([]uint8) <nil>
		      }),
		      direction: (uint8) 1,
		      requestURI: (common.NetString) (len=1 cap=446) {
		       00000000  2f                                                |/|
		      },
		      method: (common.NetString) (len=4 cap=451) {
		       00000000  50 4f 53 54                                       |POST|
		      },
		      statusCode: (uint16) 0,
		      statusPhrase: (common.NetString) <nil>,
		      realIP: (common.NetString) <nil>,
		      contentLength: (int) 85,
		      contentType: (common.NetString) (len=24 cap=157) {
		       00000000  61 70 70 6c 69 63 61 74  69 6f 6e 2f 6f 63 73 70  |application/ocsp|
		       00000010  2d 72 65 71 75 65 73 74                           |-request|
		      },
		      encodings: ([]string) <nil>,
		      isChunked: (bool) false,
		      headers: (map[string]common.NetString) {
		      },
		      size: (uint64) 451,
		      rawHeaders: ([]uint8) (len=366 cap=451) {
		       00000000  50 4f 53 54 20 2f 20 48  54 54 50 2f 31 2e 31 0d  |POST / HTTP/1.1.|
		       00000010  0a 48 6f 73 74 3a 20 6f  63 73 70 2e 69 6e 74 2d  |.Host: ocsp.int-|
		       00000020  78 33 2e 6c 65 74 73 65  6e 63 72 79 70 74 2e 6f  |x3.letsencrypt.o|
		       00000030  72 67 0d 0a 55 73 65 72  2d 41 67 65 6e 74 3a 20  |rg..User-Agent: |
		       00000040  4d 6f 7a 69 6c 6c 61 2f  35 2e 30 20 28 58 31 31  |Mozilla/5.0 (X11|
		       00000050  3b 20 46 65 64 6f 72 61  3b 20 4c 69 6e 75 78 20  |; Fedora; Linux |
		       00000060  78 38 36 5f 36 34 3b 20  72 76 3a 36 33 2e 30 29  |x86_64; rv:63.0)|
		       00000070  20 47 65 63 6b 6f 2f 32  30 31 30 30 31 30 31 20  | Gecko/20100101 |
		       00000080  46 69 72 65 66 6f 78 2f  36 33 2e 30 0d 0a 41 63  |Firefox/63.0..Ac|
		       00000090  63 65 70 74 3a 20 74 65  78 74 2f 68 74 6d 6c 2c  |cept: text/html,|
		       000000a0  61 70 70 6c 69 63 61 74  69 6f 6e 2f 78 68 74 6d  |application/xhtm|
		       000000b0  6c 2b 78 6d 6c 2c 61 70  70 6c 69 63 61 74 69 6f  |l+xml,applicatio|
		       000000c0  6e 2f 78 6d 6c 3b 71 3d  30 2e 39 2c 2a 2f 2a 3b  |n/xml;q=0.9, / ;|
		       000000d0  71 3d 30 2e 38 0d 0a 41  63 63 65 70 74 2d 4c 61  |q=0.8..Accept-La|
		       000000e0  6e 67 75 61 67 65 3a 20  65 6e 2d 55 53 2c 65 6e  |nguage: en-US,en|
		       000000f0  3b 71 3d 30 2e 35 0d 0a  41 63 63 65 70 74 2d 45  |;q=0.5..Accept-E|
		       00000100  6e 63 6f 64 69 6e 67 3a  20 67 7a 69 70 2c 20 64  |ncoding: gzip, d|
		       00000110  65 66 6c 61 74 65 0d 0a  43 6f 6e 74 65 6e 74 2d  |eflate..Content-|
		       00000120  54 79 70 65 3a 20 61 70  70 6c 69 63 61 74 69 6f  |Type: applicatio|
		       00000130  6e 2f 6f 63 73 70 2d 72  65 71 75 65 73 74 0d 0a  |n/ocsp-request..|
		       00000140  43 6f 6e 74 65 6e 74 2d  4c 65 6e 67 74 68 3a 20  |Content-Length: |
		       00000150  38 35 0d 0a 43 6f 6e 6e  65 63 74 69 6f 6e 3a 20  |85..Connection: |
		       00000160  6b 65 65 70 2d 61 6c 69  76 65 0d 0a 0d 0a        |keep-alive....|
		      },
		      sendBody: (bool) false,
		      saveBody: (bool) false,
		      body: ([]uint8) <nil>,
		      notes: ([]string) <nil>,
		      next: (*http.message)(<nil>)
		     })
		    },
		    responses: (http.messageList) {
		     head: (*http.message)(<nil>),
		     tail: (*http.message)(<nil>)
		    }
		   })

	*/
	if conn == nil {
		return nil
	}
	return conn
}

func ensureHTTPConnection(private protos.ProtocolData) *httpConnectionData {
	conn := getHTTPConnection(private)
	if conn == nil {
		conn = &httpConnectionData{}
	}
	return conn
}

func getHTTPConnection(private protos.ProtocolData) *httpConnectionData {
	if private == nil {
		return nil
	}

	priv, ok := private.(*httpConnectionData)
	if !ok {
		logp.Warn("http connection data type error")
		return nil
	}
	if priv == nil {
		logp.Warn("Unexpected: http connection data not set")
		return nil
	}

	return priv
}

// Parse function is used to process TCP payloads.
func (http *httpPlugin) doParse(
	conn *httpConnectionData,
	pkt *protos.Packet,
	tcptuple *common.TCPTuple,
	dir uint8,
) *httpConnectionData {

	if isDetailed {
		detailedf("Payload received: [%s]", pkt.Payload)
	}

	extraMsgSize := 0 // size of a "seen" packet for which we don't store the actual bytes

	st := conn.streams[dir]

	if st == nil {
		st = newStream(pkt, tcptuple)
		conn.streams[dir] = st
	} else {
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
	}

	for len(st.data) > 0 || extraMsgSize > 0 {
		if st.message == nil {
			st.message = &message{ts: pkt.Ts}
		}

		parser := newParser(&http.parserConfig)
		ok, complete := parser.parse(st, extraMsgSize)
		extraMsgSize = 0
		if !ok {
			// drop this tcp stream. Will retry parsing with the next
			// segment in it
			conn.streams[dir] = nil
			return conn
		}

		if !complete {
			// wait for more data
			break
		}

		// all ok, ship it
		http.messageComplete(conn, tcptuple, dir, st)

		// and reset stream for next message
		st.PrepareForNewMessage()
	}

	return conn
}

func newStream(pkt *protos.Packet, tcptuple *common.TCPTuple) *stream {
	return &stream{
		tcptuple: tcptuple,
		data:     pkt.Payload,
		message:  &message{ts: pkt.Ts},
	}
}

// ReceivedFin will be called when TCP transaction is terminating.
func (http *httpPlugin) ReceivedFin(tcptuple *common.TCPTuple, dir uint8,
	private protos.ProtocolData) protos.ProtocolData {

	debugf("Received FIN")
	conn := getHTTPConnection(private)
	if conn == nil {
		return private
	}

	stream := conn.streams[dir]
	if stream == nil {
		return conn
	}

	// send whatever data we got so far as complete. This
	// is needed for the HTTP/1.0 without Content-Length situation.
	if stream.message != nil {
		http.handleHTTP(conn, stream.message, tcptuple, dir)

		// and reset message. Probably not needed, just to be sure.
		stream.PrepareForNewMessage()
	}

	return conn
}

// GapInStream is called when a gap of nbytes bytes is found in the stream (due
// to packet loss).
func (http *httpPlugin) GapInStream(tcptuple *common.TCPTuple, dir uint8,
	nbytes int, private protos.ProtocolData) (priv protos.ProtocolData, drop bool) {

	defer logp.Recover("GapInStream(http) exception")

	conn := getHTTPConnection(private)
	if conn == nil {
		return private, false
	}

	stream := conn.streams[dir]
	if stream == nil || stream.message == nil {
		// nothing to do
		return private, false
	}

	ok, complete := http.messageGap(stream, nbytes)
	if isDetailed {
		detailedf("messageGap returned ok=%v complete=%v", ok, complete)
	}
	if !ok {
		// on errors, drop stream
		conn.streams[dir] = nil
		return conn, true
	}

	if complete {
		// Current message is complete, we need to publish from here
		http.messageComplete(conn, tcptuple, dir, stream)
	}

	// don't drop the stream, we can ignore the gap
	return private, false
}

func (http *httpPlugin) handleHTTP(
	conn *httpConnectionData,
	m *message,
	tcptuple *common.TCPTuple,
	dir uint8,
) {

	m.tcpTuple = *tcptuple
	m.direction = dir
	m.cmdlineTuple = procs.ProcWatcher.FindProcessesTupleTCP(tcptuple.IPPort())
	http.hideHeaders(m)

	if m.isRequest {
		if isDebug {
			debugf("Received request with tuple: %s", m.tcpTuple)
		}
		conn.requests.append(m)
	} else {
		if isDebug {
			debugf("Received response with tuple: %s", m.tcpTuple)
		}
		conn.responses.append(m)
		http.correlate(conn)
	}
}

func (http *httpPlugin) flushResponses(conn *httpConnectionData) {
	for !conn.responses.empty() {
		unmatchedResponses.Add(1)
		resp := conn.responses.pop()
		debugf("Response from unknown transaction: %s. Reporting error.", resp.tcpTuple)
		event := http.newTransaction(nil, resp)
		http.publishTransaction(event)
	}
}

func (http *httpPlugin) flushRequests(conn *httpConnectionData) {
	for !conn.requests.empty() {
		unmatchedRequests.Add(1)
		requ := conn.requests.pop()
		debugf("Request from unknown transaction %s. Reporting error.", requ.tcpTuple)
		event := http.newTransaction(requ, nil)
		http.publishTransaction(event)
	}
}

func (http *httpPlugin) correlate(conn *httpConnectionData) {

	// drop responses with missing requests
	if conn.requests.empty() {
		http.flushResponses(conn)
		return
	}

	// merge requests with responses into transactions
	for !conn.responses.empty() && !conn.requests.empty() {
		requ := conn.requests.pop()
		resp := conn.responses.pop()
		event := http.newTransaction(requ, resp)

		if isDebug {
			debugf("HTTP transaction completed")
		}
		http.publishTransaction(event)
	}
}

func (http *httpPlugin) newTransaction(requ, resp *message) beat.Event {
	status := common.OK_STATUS
	if resp == nil {
		status = common.ERROR_STATUS
		if requ != nil {
			requ.notes = append(requ.notes, "Unmatched request")
		}
	} else if resp.statusCode >= 400 {
		status = common.ERROR_STATUS
	}
	if requ == nil {
		status = common.ERROR_STATUS
		if resp != nil {
			resp.notes = append(resp.notes, "Unmatched response")
		}
	}

	httpDetails := common.MapStr{}
	fields := common.MapStr{
		"type":   "http",
		"status": status,
		"http":   httpDetails,
	}

	var timestamp time.Time

	if requ != nil {
		// Body must be decoded before extractParameters
		http.decodeBody(requ)
		path, params, err := http.extractParameters(requ)
		if err != nil {
			logp.Warn("Fail to parse HTTP parameters: %v", err)
		}
		httpDetails["request"] = common.MapStr{
			"params":  params,
			"headers": http.collectHeaders(requ),
		}
		fields["method"] = requ.method
		fields["path"] = path
		fields["query"] = fmt.Sprintf("%s %s", requ.method, path)
		fields["bytes_in"] = requ.size

		fields["src"], fields["dst"] = requ.getEndpoints()

		http.setBody(httpDetails["request"].(common.MapStr), requ)

		timestamp = requ.ts

		if len(requ.notes) > 0 {
			fields["notes"] = requ.notes
		}

		if len(requ.realIP) > 0 {
			fields["real_ip"] = requ.realIP
		}

		if http.sendRequest {
			fields["request"] = string(http.makeRawMessage(requ))
		}
	}

	if resp != nil {
		http.decodeBody(resp)
		httpDetails["response"] = common.MapStr{
			"code":    resp.statusCode,
			"phrase":  resp.statusPhrase,
			"headers": http.collectHeaders(resp),
		}
		http.setBody(httpDetails["response"].(common.MapStr), resp)
		fields["bytes_out"] = resp.size

		if http.sendResponse {
			fields["response"] = string(http.makeRawMessage(resp))
		}

		if len(resp.notes) > 0 {
			if fields["notes"] != nil {
				fields["notes"] = append(fields["notes"].([]string), resp.notes...)
			} else {
				fields["notes"] = resp.notes
			}
		}
		if requ == nil {
			timestamp = resp.ts
			fields["src"], fields["dst"] = resp.getEndpoints()
		}
	}

	// resp_time in milliseconds
	if requ != nil && resp != nil {
		fields["responsetime"] = int32(resp.ts.Sub(requ.ts).Nanoseconds() / 1e6)
	}

	/*
		runtime/debug.Stack(0x3800000ed3a610dd, 0xc001791740, 0x38247b8d78eae0b4)
		        /usr/local/go/src/runtime/debug/stack.go:24 +0xa7
		runtime/debug.PrintStack()
		        /usr/local/go/src/runtime/debug/stack.go:16 +0x22
		github.com/elastic/beats/packetbeat/protos/http.(*httpPlugin).newTransaction(0xc001782420, 0xc001765e00, 0xc00109c000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0)
		        /root/go/src/github.com/elastic/beats/packetbeat/protos/http/http.go:772 +0x279
		github.com/elastic/beats/packetbeat/protos/http.(*httpPlugin).correlate(0xc001782420, 0xc000f17350)
		        /root/go/src/github.com/elastic/beats/packetbeat/protos/http/http.go:670 +0x12f
		github.com/elastic/beats/packetbeat/protos/http.(*httpPlugin).handleHTTP(0xc001782420, 0xc000f17350, 0xc00109c000, 0xc00003a648, 0xc00109c000)
		        /root/go/src/github.com/elastic/beats/packetbeat/protos/http/http.go:634 +0x2bf
		github.com/elastic/beats/packetbeat/protos/http.(*httpPlugin).messageComplete(0xc001782420, 0xc000f17350, 0xc00003a648, 0x100, 0xc00045eb00)
		        /root/go/src/github.com/elastic/beats/packetbeat/protos/http/http.go:227 +0x56
		github.com/elastic/beats/packetbeat/protos/http.(*httpPlugin).doParse(0xc001782420, 0xc000f17350, 0xc000f7d500, 0xc00003a648, 0x7fdf666e4a00, 0xc001782420)
		        /root/go/src/github.com/elastic/beats/packetbeat/protos/http/http.go:531 +0x1f3
		github.com/elastic/beats/packetbeat/protos/http.(*httpPlugin).Parse(0xc001782420, 0xc000f7d500, 0xc00003a648, 0xc001782400, 0x15af2a0, 0xc000f17350, 0x0, 0x0)
		        /root/go/src/github.com/elastic/beats/packetbeat/protos/http/http.go:275 +0xab
		github.com/elastic/beats/packetbeat/protos/tcp.(*TCPStream).addPacket(0xc001791cb0, 0xc000f7d500, 0xc0011492a0)
		        /root/go/src/github.com/elastic/beats/packetbeat/protos/tcp/tcp.go:145 +0x159
		github.com/elastic/beats/packetbeat/protos/tcp.(*TCP).Process(0xc001384d70, 0xc0000c4cc0, 0xc0011492a0, 0xc000f7d500)
		        /root/go/src/github.com/elastic/beats/packetbeat/protos/tcp/tcp.go:240 +0x327
		github.com/elastic/beats/packetbeat/decoder.(*Decoder).onTCP(0xc001148d00, 0xc000f7d500)
		        /root/go/src/github.com/elastic/beats/packetbeat/decoder/decoder.go:334 +0xdd
		github.com/elastic/beats/packetbeat/decoder.(*Decoder).process(0xc001148d00, 0xc000f7d500, 0x2c, 0x180, 0x193efa0, 0xc001148d00)
		        /root/go/src/github.com/elastic/beats/packetbeat/decoder/decoder.go:275 +0x1dd
		github.com/elastic/beats/packetbeat/decoder.(*Decoder).OnPacket(0xc001148d00, 0xc0017b4b84, 0x180, 0x180, 0xc000f17470)
		        /root/go/src/github.com/elastic/beats/packetbeat/decoder/decoder.go:181 +0x317
		github.com/elastic/beats/packetbeat/sniffer.(*Sniffer).Run(0xc001782b00, 0x0, 0x0)
		        /root/go/src/github.com/elastic/beats/packetbeat/sniffer/sniffer.go:210 +0x466
		github.com/elastic/beats/packetbeat/beater.(*packetbeat).Run.func2(0xc001446bf0, 0xc00177e000, 0xc0012f2b40)
		        /root/go/src/github.com/elastic/beats/packetbeat/beater/packetbeat.go:225 +0x60
		created by github.com/elastic/beats/packetbeat/beater.(*packetbeat).Run
		        /root/go/src/github.com/elastic/beats/packetbeat/beater/packetbeat.go:222 +0x129
	*/

	/*
		This is what fields looks like
		(common.MapStr) (len=11) {"bytes_in":296,"bytes_out":384,"dst":{"IP":"184.24.98.240","Port":80,"Name":"","Cmdline":"","Proc":""},"http":{"request":{"headers":{"content-length":0},"params":""},"response":{"code":200,"headers":{"content-length":8,"content-type":"text/plain"},"phrase":"OK"}},"method":"GET","path":"/success.txt","query":"GET /success.txt","responsetime":24,"src":{"IP":"192.168.1.235","Port":40572,"Name":"","Cmdline":"","Proc":""},"status":"OK","type":"http"}
	*/

	return beat.Event{
		Timestamp: timestamp,
		Fields:    fields,
	}
}

func (http *httpPlugin) makeRawMessage(m *message) string {
	if m.sendBody {
		var b strings.Builder
		b.Grow(len(m.rawHeaders) + len(m.body))
		b.Write(m.rawHeaders)
		b.Write(m.body)
		return b.String()
	}
	return string(m.rawHeaders)
}

func (http *httpPlugin) publishTransaction(event beat.Event) {
	if http.results == nil {
		return
	}
	// This up being the beat event
	http.results(event)
}

func (http *httpPlugin) collectHeaders(m *message) interface{} {
	hdrs := map[string]interface{}{}

	hdrs["content-length"] = m.contentLength
	if len(m.contentType) > 0 {
		hdrs["content-type"] = m.contentType
	}

	if http.parserConfig.sendHeaders {

		cookie := "cookie"
		if !m.isRequest {
			cookie = "set-cookie"
		}

		for name, value := range m.headers {
			if strings.ToLower(name) == "content-type" {
				continue
			}
			if strings.ToLower(name) == "content-length" {
				continue
			}
			if http.splitCookie && name == cookie {
				hdrs[name] = splitCookiesHeader(string(value))
			} else {
				hdrs[name] = value
			}
		}
	}
	return hdrs
}

func (http *httpPlugin) setBody(result common.MapStr, m *message) {
	if m.sendBody && len(m.body) > 0 {
		result["body"] = string(m.body)
	}
}

func (http *httpPlugin) decodeBody(m *message) {
	if m.saveBody && len(m.body) > 0 {
		if http.mustDecodeBody && len(m.encodings) > 0 {
			var err error
			m.body, err = decodeBody(m.body, m.encodings, http.maxMessageSize)
			if err != nil {
				// Body can contain partial data
				m.notes = append(m.notes, err.Error())
			}
		}
	}
}

func decodeBody(body []byte, encodings []string, maxSize int) (result []byte, err error) {
	if isDebug {
		debugf("decoding body with encodings=%v", encodings)
	}
	for idx := len(encodings) - 1; idx >= 0; idx-- {
		format := encodings[idx]
		body, err = decodeHTTPBody(body, format, maxSize)
		if err != nil {
			// Do not output a partial body unless failure occurs on the
			// last decoder.
			if idx != 0 {
				body = nil
			}
			return body, errors.Wrapf(err, "unable to decode body using %s encoding", format)
		}
	}
	return body, nil
}

func splitCookiesHeader(headerVal string) map[string]string {
	cookies := map[string]string{}

	cstring := strings.Split(headerVal, ";")
	for _, cval := range cstring {
		cookie := strings.SplitN(cval, "=", 2)
		if len(cookie) == 2 {
			cookies[strings.ToLower(strings.TrimSpace(cookie[0]))] =
				parseCookieValue(strings.TrimSpace(cookie[1]))
		}
	}

	return cookies
}

func parseCookieValue(raw string) string {
	// Strip the quotes, if present.
	if len(raw) > 1 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		raw = raw[1 : len(raw)-1]
	}
	return raw
}

func (http *httpPlugin) hideHeaders(m *message) {
	if !m.isRequest || !http.redactAuthorization {
		return
	}

	msg := m.rawHeaders
	limit := len(msg)

	// byte64 != encryption, so obscure it in headers in case of Basic Authentication

	redactHeaders := []string{"authorization", "proxy-authorization"}
	authText := []byte("uthorization:") // [aA] case insensitive, also catches Proxy-Authorization:

	authHeaderStartX := m.headerOffset
	authHeaderEndX := limit

	for authHeaderStartX < limit {
		if isDebug {
			debugf("looking for authorization from %d to %d",
				authHeaderStartX, authHeaderEndX)
		}

		startOfHeader := bytes.Index(msg[authHeaderStartX:], authText)
		if startOfHeader >= 0 {
			authHeaderStartX = authHeaderStartX + startOfHeader

			endOfHeader := bytes.Index(msg[authHeaderStartX:], constCRLF)
			if endOfHeader >= 0 {
				authHeaderEndX = authHeaderStartX + endOfHeader

				if authHeaderEndX > limit {
					authHeaderEndX = limit
				}

				if isDebug {
					debugf("Redact authorization from %d to %d", authHeaderStartX, authHeaderEndX)
				}

				for i := authHeaderStartX + len(authText); i < authHeaderEndX; i++ {
					msg[i] = byte('*')
				}
			}
		}
		authHeaderStartX = authHeaderEndX + len(constCRLF)
		authHeaderEndX = len(m.rawHeaders)
	}

	for _, header := range redactHeaders {
		if len(m.headers[header]) > 0 {
			m.headers[header] = []byte("*")
		}
	}
}

func (http *httpPlugin) hideSecrets(values url.Values) url.Values {
	params := url.Values{}
	for key, array := range values {
		for _, value := range array {
			if http.isSecretParameter(key) {
				params.Add(key, "xxxxx")
			} else {
				params.Add(key, value)
			}
		}
	}
	return params
}

// extractParameters parses the URL and the form parameters and replaces the secrets
// with the string xxxxx. The parameters containing secrets are defined in http.Hide_secrets.
// Returns the Request URI path and the (adjusted) parameters.
func (http *httpPlugin) extractParameters(m *message) (path string, params string, err error) {
	var values url.Values

	u, err := url.Parse(string(m.requestURI))
	if err != nil {
		return
	}
	values = u.Query()
	path = u.Path

	paramsMap := http.hideSecrets(values)

	if m.contentLength > 0 && m.saveBody && bytes.Contains(m.contentType, []byte("urlencoded")) {

		values, err = url.ParseQuery(string(m.body))
		if err != nil {
			return
		}

		for key, value := range http.hideSecrets(values) {
			paramsMap[key] = value
		}
	}

	params = paramsMap.Encode()
	if isDetailed {
		detailedf("Form parameters: %s", params)
	}
	return
}

func (http *httpPlugin) isSecretParameter(key string) bool {
	for _, keyword := range http.hideKeywords {
		if strings.ToLower(key) == keyword {
			return true
		}
	}
	return false
}

func (http *httpPlugin) Expired(tuple *common.TCPTuple, private protos.ProtocolData) {
	conn := getHTTPConnection(private)
	if conn == nil {
		return
	}
	if isDebug {
		debugf("expired connection %s", tuple)
	}
	// terminate streams
	for dir, s := range conn.streams {
		// Do not send incomplete or empty messages
		if s != nil && s.message != nil && s.message.headersReceived() {
			if isDebug {
				debugf("got message %+v", s.message)
			}
			http.handleHTTP(conn, s.message, tuple, uint8(dir))
			s.PrepareForNewMessage()
		}
	}
	// correlate transactions
	http.correlate(conn)

	// flush uncorrelated requests and responses
	http.flushRequests(conn)
	http.flushResponses(conn)
}

func (ml *messageList) append(msg *message) {
	if ml.tail == nil {
		ml.head = msg
	} else {
		ml.tail.next = msg
	}
	msg.next = nil
	ml.tail = msg
}

func (ml *messageList) empty() bool {
	return ml.head == nil
}

func (ml *messageList) pop() *message {
	if ml.head == nil {
		return nil
	}

	msg := ml.head
	ml.head = ml.head.next
	if ml.head == nil {
		ml.tail = nil
	}
	return msg
}

func (ml *messageList) last() *message {
	return ml.tail
}
