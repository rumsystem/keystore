package options

import (
	"github.com/spf13/viper"
	"sync"
)

type NodeOptions struct {
	SignKeyMap map[string]string
	mu         sync.RWMutex
}

var nodeopts *NodeOptions
var nodeconfigdir string
var nodepeername string

func InitNodeOptions(configdir, peername string) (*NodeOptions, error) {
	var err error
	nodeopts, err = load(configdir, peername)
	if err == nil {
		nodeconfigdir = configdir
		nodepeername = peername
	}
	return nodeopts, err
}

func load(dir string, keyname string) (*NodeOptions, error) {
	v, err := initConfigfile(dir, keyname)
	if err != nil {
		return nil, err
	}
	err = v.ReadInConfig()
	if err != nil {
		return nil, err
	}

	options := &NodeOptions{}
	options.SignKeyMap = v.GetStringMapString("SignKeyMap")
	return options, nil
}

func (opt *NodeOptions) SetSignKeyMap(keyname, addr string) error {
	opt.mu.Lock()
	defer opt.mu.Unlock()
	opt.SignKeyMap[keyname] = addr
	return opt.writeToconfig()
}

func (opt *NodeOptions) DelSignKeyMap(keyname string) error {
	opt.mu.Lock()
	defer opt.mu.Unlock()
	delete(opt.SignKeyMap, keyname)
	return opt.writeToconfig()
}

func initConfigfile(dir string, keyname string) (*viper.Viper, error) {
	v := viper.New()
	v.SetConfigFile(keyname + "_options.toml")
	v.SetConfigName(keyname + "_options")
	v.SetConfigType("toml")
	v.AddConfigPath(dir)

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			writeDefaultToconfig(v)
		} else {
			return nil, err
		}
	}

	return v, nil
}

func writeDefaultToconfig(v *viper.Viper) error {
	v.Set("SignKeyMap", map[string]string{})
	return v.SafeWriteConfig()
}

func (opt *NodeOptions) writeToconfig() error {
	v, err := initConfigfile(nodeconfigdir, nodepeername)
	if err != nil {
		return err
	}
	v.Set("SignKeyMap", opt.SignKeyMap)
	return v.WriteConfig()
}
