package wgg

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/go-ini/ini"
	"golang.zx2c4.com/wireguard/wgctrl"
)

func init() {
	ini.PrettyFormat = false
	ini.PrettyEqual = true
}

func cmdShowConf(args []string) error {
	c, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("error creating client: %w", err)
	}
	defer c.Close()

	name := args[0]
	d, err := c.Device(name)
	if err != nil {
		return fmt.Errorf("error getting device %s: %w", name, err)
	}

	conf := ini.Empty(ini.LoadOptions{AllowNonUniqueSections: true})

	// Ignore errors
	sec, _ := conf.NewSection("Interface")
	if d.ListenPort != 0 {
		sec.NewKey("ListenPort", strconv.Itoa(d.ListenPort))
	}
	if d.FirewallMark != 0 {
		sec.NewKey("FwMark", fmt.Sprintf("0x%x", d.FirewallMark))
	}
	if !keyIsZero(d.PrivateKey) {
		sec.NewKey("PrivateKey", d.PrivateKey.String())
	}

	for _, p := range d.Peers {
		sec, _ = conf.NewSection("Peer")
		sec.NewKey("PublicKey", p.PublicKey.String())
		if !keyIsZero(p.PresharedKey) {
			sec.NewKey("PresharedKey", p.PresharedKey.String())
		}

		ips := make([]string, 0, len(p.AllowedIPs))
		for _, ip := range p.AllowedIPs {
			ips = append(ips, ip.String())
		}
		if len(ips) > 0 {
			sec.NewKey("AllowedIPs", strings.Join(ips, ", "))
		}

		if p.Endpoint != nil {
			sec.NewKey("Endpoint", p.Endpoint.String())
		}
		if p.PersistentKeepaliveInterval != 0 {
			val := fmt.Sprintf("%.0f", p.PersistentKeepaliveInterval.Seconds())
			sec.NewKey("PersistentKeepalive", val)
		}
	}

	if _, err := conf.WriteTo(os.Stdout); err != nil {
		return fmt.Errorf("error writing config to stdout: %w", err)
	}
	return nil
}
