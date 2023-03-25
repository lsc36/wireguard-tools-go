package wgg

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type configParser struct {
	Cfg *wgtypes.Config
}

func (cp configParser) ParsePrivateKey(s string) error {
	// An empty string clears the key.
	if s == "" {
		cp.Cfg.PrivateKey = &wgtypes.Key{}
		return nil
	}
	key, err := wgtypes.ParseKey(s)
	if err != nil {
		return err
	}
	cp.Cfg.PrivateKey = &key
	return nil
}

func (cp configParser) ParseListenPort(s string) error {
	port, err := strconv.Atoi(s)
	if err != nil {
		return err
	}
	cp.Cfg.ListenPort = &port
	return nil
}

func (cp configParser) ParseFirewallMark(s string) error {
	fwmark := 0
	// "off" is equivalent to 0
	if s != "off" {
		var err error
		fwmark, err = strconv.Atoi(s)
		if err != nil {
			return err
		}
	}
	cp.Cfg.FirewallMark = &fwmark
	return nil
}

type peerConfigParser struct {
	Cfg *wgtypes.PeerConfig
}

func (pcp peerConfigParser) ParsePublicKey(s string) error {
	var err error
	pcp.Cfg.PublicKey, err = wgtypes.ParseKey(s)
	return err
}

func (pcp peerConfigParser) ParseAllowedIPs(s string) error {
	for _, ipmask := range strings.Split(s, ",") {
		ipmask = strings.TrimSpace(ipmask)

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
			return fmt.Errorf("error parsing CIDR: %w", err)
		}
		if !ip.Equal(net.IP) {
			return fmt.Errorf("AllowedIP has nonzero host part: %s", ipmask)
		}

		pcp.Cfg.AllowedIPs = append(pcp.Cfg.AllowedIPs, *net)
	}
	return nil
}
