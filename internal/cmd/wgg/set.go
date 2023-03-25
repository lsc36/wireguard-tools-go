package wgg

import (
	"fmt"
	"os"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func cmdSet(args []string) error {
	c, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("error creating client: %w", err)
	}
	defer c.Close()

	cfg := wgtypes.Config{}
	cp := configParser{Cfg: &cfg}

	dev, args := args[0], args[1:]
	for len(args) > 0 {
		if args, err = parseOneConfigValue(args, cp); err != nil {
			return err
		}
	}

	if err := c.ConfigureDevice(dev, cfg); err != nil {
		return fmt.Errorf("error configuring device %s: %w", dev, err)
	}
	return nil
}

func parseOneConfigValue(args []string, cp configParser) ([]string, error) {
	errInvalid := fmt.Errorf("invalid argument: %s", args[0])

	switch args[0] {
	case "listen-port":
		if len(args) < 2 {
			return nil, errInvalid
		}
		if err := cp.ParseListenPort(args[1]); err != nil {
			return nil, fmt.Errorf("error parsing listen-port: %w", err)
		}
		args = args[2:]

	case "fwmark":
		if len(args) < 2 {
			return nil, errInvalid
		}
		if err := cp.ParseFirewallMark(args[1]); err != nil {
			return nil, fmt.Errorf("error parsing fwmark: %w", err)
		}
		args = args[2:]

	case "private-key":
		if len(args) < 2 {
			return nil, errInvalid
		}

		data, err := os.ReadFile(args[1])
		if err != nil {
			return nil, fmt.Errorf("error reading private-key: %w", err)
		}

		if err := cp.ParsePrivateKey(strings.TrimSpace(string(data))); err != nil {
			return nil, fmt.Errorf("error parsing private-key: %w", err)
		}
		args = args[2:]

	case "peer":
		if len(args) < 2 {
			return nil, errInvalid
		}

		pc := wgtypes.PeerConfig{}
		pcp := peerConfigParser{Cfg: &pc}

		if err := pcp.ParsePublicKey(args[1]); err != nil {
			return nil, fmt.Errorf("error parsing peer key: %w", err)
		}

		args = args[2:]
		var done bool
		var err error
		for !done && len(args) > 0 {
			if args, done, err = parseOnePeerConfigValue(args, pcp); err != nil {
				return nil, err
			}
		}

		cp.Cfg.Peers = append(cp.Cfg.Peers, pc)

	default:
		return nil, errInvalid
	}

	return args, nil
}

func parseOnePeerConfigValue(args []string, pcp peerConfigParser) ([]string, bool, error) {
	done := false
	errInvalid := fmt.Errorf("invalid argument: %s", args[0])

	switch args[0] {
	case "remove":
		pcp.Cfg.Remove = true
		args = args[1:]

	// TODO implement the following
	//case "preshared-key":
	//case "endpoint":
	//case "persistent-keepalive":

	case "allowed-ips":
		if len(args) < 2 {
			return nil, false, errInvalid
		}

		pcp.Cfg.ReplaceAllowedIPs = true
		if args[1] != "" {
			if err := pcp.ParseAllowedIPs(args[1]); err != nil {
				return nil, false, fmt.Errorf("error parsing allowed-ips: %w", err)
			}
		}
		args = args[2:]

	case "peer":
		done = true

	default:
		return nil, false, errInvalid
	}

	return args, done, nil
}
