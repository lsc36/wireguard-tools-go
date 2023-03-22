package wgg

import (
	"fmt"
	"net"
	"os"
	"strconv"
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

	var cfg wgtypes.Config
	dev, args := args[0], args[1:]
	for len(args) > 0 {
		if args, err = parseOneConfigValue(args, &cfg); err != nil {
			return err
		}
	}

	if err := c.ConfigureDevice(dev, cfg); err != nil {
		return fmt.Errorf("error configuring device %s: %w", dev, err)
	}
	return nil
}

func parseOneConfigValue(args []string, cfg *wgtypes.Config) ([]string, error) {
	errInvalid := fmt.Errorf("invalid argument: %s", args[0])

	switch args[0] {
	case "listen-port":
		if len(args) < 2 {
			return nil, errInvalid
		}

		port, err := strconv.Atoi(args[1])
		if err != nil {
			return nil, fmt.Errorf("error parsing listen-port: %w", err)
		}

		cfg.ListenPort = &port
		args = args[2:]

	case "fwmark":
		if len(args) < 2 {
			return nil, errInvalid
		}

		var fwmark int
		// "off" is equivalent to 0
		if args[1] != "off" {
			var err error
			fwmark, err = strconv.Atoi(args[1])
			if err != nil {
				return nil, fmt.Errorf("error parsing fwmark: %w", err)
			}
		}

		cfg.FirewallMark = &fwmark
		args = args[2:]

	case "private-key":
		if len(args) < 2 {
			return nil, errInvalid
		}

		data, err := os.ReadFile(args[1])
		if err != nil {
			return nil, fmt.Errorf("error reading private-key: %w", err)
		}

		var key wgtypes.Key
		// An empty file clears the key.
		if len(data) > 0 {
			key, err = wgtypes.ParseKey(strings.TrimSpace(string(data)))
			if err != nil {
				return nil, fmt.Errorf("error parsing private-key: %w", err)
			}
		}

		cfg.PrivateKey = &key
		args = args[2:]

	case "peer":
		if len(args) < 2 {
			return nil, errInvalid
		}

		key, err := wgtypes.ParseKey(args[1])
		if err != nil {
			return nil, fmt.Errorf("error parsing peer key: %w", err)
		}

		pc := wgtypes.PeerConfig{PublicKey: key}
		args = args[2:]
		var done bool
		for !done && len(args) > 0 {
			if args, done, err = parseOnePeerConfigValue(args, &pc); err != nil {
				return nil, err
			}
		}

		cfg.Peers = append(cfg.Peers, pc)

	default:
		return nil, errInvalid
	}

	return args, nil
}

func parseOnePeerConfigValue(args []string, pc *wgtypes.PeerConfig) ([]string, bool, error) {
	done := false
	errInvalid := fmt.Errorf("invalid argument: %s", args[0])

	switch args[0] {
	case "remove":
		pc.Remove = true
		args = args[1:]

	// TODO implement the following
	//case "preshared-key":
	//case "endpoint":
	//case "persistent-keepalive":

	case "allowed-ips":
		if len(args) < 2 {
			return nil, false, errInvalid
		}

		pc.ReplaceAllowedIPs = true

		if args[1] != "" {
			for _, ipmask := range strings.Split(args[1], ",") {
				// Add all-ones mask if no mask is specified.
				if !strings.Contains(ipmask, "/") {
					if strings.Contains(ipmask, ":") {
						// IPv6
						ipmask += "/128"
					} else {
						// IPv4
						ipmask += "/32"
					}
				}

				ip, net, err := net.ParseCIDR(ipmask)
				if err != nil {
					return nil, false, fmt.Errorf("error parsing CIDR: %w", err)
				}
				if !ip.Equal(net.IP) {
					return nil, false, fmt.Errorf("AllowedIP has nonzero host part: %s", ipmask)
				}

				pc.AllowedIPs = append(pc.AllowedIPs, *net)
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
