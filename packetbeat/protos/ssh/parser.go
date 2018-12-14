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
	"time"

	"github.com/elastic/beats/libbeat/common/streambuf"
	"github.com/elastic/beats/packetbeat/protos/applayer"
)

type parser struct {
	buf     streambuf.Buffer
	config  *parserConfig
	message *message

	onMessage func(m *message) error
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

func (p *parser) init(
	cfg *parserConfig,
	onMessage func(*message) error,
) {
	*p = parser{
		buf:       streambuf.Buffer{},
		config:    cfg,
		onMessage: onMessage,
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

	if err := p.append(data); err != nil {
		return err
	}

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
