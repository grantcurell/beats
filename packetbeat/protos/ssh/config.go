package ssh

import (
	"github.com/elastic/beats/packetbeat/config"
	"github.com/elastic/beats/packetbeat/protos"
)

type sshConfig struct {
	config.ProtocolCommon `config:",inline"`
}

var (
	defaultConfig = sshConfig{
		ProtocolCommon: config.ProtocolCommon{
			TransactionTimeout: protos.DefaultTransactionExpiration,
		},
	}
)

func (c *sshConfig) Validate() error {
	return nil
}
