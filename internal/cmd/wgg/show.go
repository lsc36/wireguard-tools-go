package wgg

import (
	"fmt"
	"strings"

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
	// TODO show all available attributes; skip empty ones
	fmt.Printf(`interface: %s
  public key: %s
  private key: (hidden)
  listening port: %d
`, d.Name, d.PublicKey, d.ListenPort)

	for _, p := range d.Peers {
		allowedIPs := make([]string, 0, len(p.AllowedIPs))
		for _, ip := range p.AllowedIPs {
			allowedIPs = append(allowedIPs, ip.String())
		}

		fmt.Printf(`
peer: %s
  allowed ips: %s
`, p.PublicKey, strings.Join(allowedIPs, ", "))
	}
}
