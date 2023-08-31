package config

import (
	"io/ioutil"

	"github.com/shu1r0/srv6ptf_ebpfagent/pkg/ebpf"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Routes struct {
		Add struct {
			EndInsertId []ebpf.Seg6LocalEndInsertIdRoute `yaml:"end_insert_id"`
			XmitReadId  []ebpf.LWTReadIdRoute            `yaml:"xmit_read_id"`
			InReadId    []ebpf.LWTReadIdRoute            `yaml:"in_read_id"`
			OutReadId   []ebpf.LWTReadIdRoute            `yaml:"out_read_id"`
		} `yaml:"add"`
	} `yaml:"routes"`
}

func ParseConfData(data []byte) (*Config, error) {
	routeConf := &Config{}

	if err := yaml.Unmarshal(data, routeConf); err != nil {
		return nil, err
	}

	return routeConf, nil
}

func ParseConfFile(path string) (*Config, error) {
	yamlF, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseConfData(yamlF)
}
