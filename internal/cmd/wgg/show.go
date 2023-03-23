package wgg

import (
	"fmt"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func cmdShowAll(args []string) error {
	c, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("error creating client: %w", err)
	}
	defer c.Close()

	// TODO implement show specific attribute
	ds, err := c.Devices()
	if err != nil {
		return fmt.Errorf("error getting devices: %w", err)
	}

	for i, d := range ds {
		if i != 0 {
			fmt.Println("")
		}
		showDevice(d)
	}
	return nil
}

func cmdShowInterfaces(args []string) error {
	c, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("error creating client: %w", err)
	}
	defer c.Close()

	ds, err := c.Devices()
	if err != nil {
		return fmt.Errorf("error getting devices: %w", err)
	}

	for _, d := range ds {
		fmt.Println(d.Name)
	}
	return nil
}

func cmdShowOne(args []string) error {
	if len(args) == 0 {
		return cmdShowAll(args)
	}

	c, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("error creating client: %w", err)
	}
	defer c.Close()

	// TODO implement show specific field
	name := args[0]

	d, err := c.Device(name)
	if err != nil {
		return fmt.Errorf("error getting device %s: %w", name, err)
	}

	showDevice(d)
	return nil
}

func showDevice(d *wgtypes.Device) {
	s := fmt.Sprintf("interface: %s\n", d.Name)
	if !keyIsZero(d.PrivateKey) {
		s += fmt.Sprintf("  public key: %s\n", d.PublicKey)
		s += "  private key: (hidden)\n"
	}
	if d.ListenPort != 0 {
		s += fmt.Sprintf("  listening port: %d\n", d.ListenPort)
	}
	if d.FirewallMark != 0 {
		s += fmt.Sprintf("  fwmark: 0x%x\n", d.FirewallMark)
	}
	fmt.Print(s)

	for _, p := range d.Peers {
		s := fmt.Sprintf("\npeer: %s\n", p.PublicKey)
		if !keyIsZero(p.PresharedKey) {
			s += "  preshared key: (hidden)\n"
		}
		if p.Endpoint != nil {
			s += fmt.Sprintf("  endpoint: %s\n", p.Endpoint)
		}

		allowedIPs := make([]string, 0, len(p.AllowedIPs))
		for _, ip := range p.AllowedIPs {
			allowedIPs = append(allowedIPs, ip.String())
		}
		if len(allowedIPs) > 0 {
			s += fmt.Sprintf("  allowed ips: %s\n", strings.Join(allowedIPs, ", "))
		} else {
			s += "  allowed ips: (none)\n"
		}

		if !p.LastHandshakeTime.IsZero() {
			// TODO match wg output format
			ago := time.Now().Sub(p.LastHandshakeTime).Truncate(time.Second)
			s += fmt.Sprintf("  latest handshake: %s ago\n", ago)
		}
		if p.ReceiveBytes != 0 || p.TransmitBytes != 0 {
			// TODO match wg output format
			rx := fmt.Sprintf("%d B", p.ReceiveBytes)
			tx := fmt.Sprintf("%d B", p.TransmitBytes)
			s += fmt.Sprintf("  transfer: %s received, %s sent\n", rx, tx)
		}
		if p.PersistentKeepaliveInterval != 0 {
			// TODO match wg output format
			d := p.PersistentKeepaliveInterval.Truncate(time.Second)
			s += fmt.Sprintf("  persistent keepalive: every %s\n", d)
		}

		fmt.Print(s)
	}
}
