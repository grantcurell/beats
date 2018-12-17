package ssh

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/common"

	"github.com/elastic/beats/packetbeat/protos"
)

type transPub struct {
	sendRequest  bool
	sendResponse bool

	results protos.Reporter // TODO this is what ultimately has to be filled
}

func (pub *transPub) onTransaction(requ, resp *message) error {
	if pub.results == nil {
		return nil
	}
	fmt.Println("HERE2")
	pub.results(pub.createEvent(requ, resp))
	return nil
}

func (pub *transPub) createEvent(requ, resp *message) beat.Event {
	status := common.OK_STATUS
	debug.PrintStack()
	os.Exit(3)

	// resp_time in milliseconds
	responseTime := int32(resp.Ts.Sub(requ.Ts).Nanoseconds() / 1e6)

	src := &common.Endpoint{
		IP:   requ.Tuple.SrcIP.String(),
		Port: requ.Tuple.SrcPort,
		Proc: string(requ.CmdlineTuple.Src),
	}
	dst := &common.Endpoint{
		IP:   requ.Tuple.DstIP.String(),
		Port: requ.Tuple.DstPort,
		Proc: string(requ.CmdlineTuple.Dst),
	}

	fields := common.MapStr{
		"type":         "ssh",
		"status":       status,
		"responsetime": responseTime,
		"bytes_in":     requ.Size,
		"bytes_out":    resp.Size,
		"src":          src,
		"dst":          dst,
		"Client Info":  requ.info,
		"Server Info":  resp.info,
	}

	// add processing notes/errors to event
	if len(requ.Notes)+len(resp.Notes) > 0 {
		fields["notes"] = append(requ.Notes, resp.Notes...)
	}

	/*
		EXTRA
		if pub.sendRequest {
			// fields["request"] =
		}
		if pub.sendResponse {
			// fields["response"] =
		}*/

	return beat.Event{
		Timestamp: requ.Ts,
		Fields:    fields,
	}
}
