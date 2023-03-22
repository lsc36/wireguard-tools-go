package wgg

type errUsage string

func (e errUsage) Error() string {
	return "Usage: " + string(e)
}

const (
	usage     = "wg <cmd> [args]"
	usageShow = "wg show { <interface> | all | interfaces } [public-key | private-key | listen-port | fwmark | peers | preshared-keys | endpoints | allowed-ips | latest-handshakes | transfer | persistent-keepalive | dump]"
)

type command struct {
	Func        func([]string) error
	Usage       errUsage
	MinNArgs    int
	MaxNArgs    int
	Subcommands map[string]*command
}

var commandRoot = &command{
	Func:  cmdShowAll,
	Usage: usage,
	Subcommands: map[string]*command{
		"show": {
			Func:     cmdShowOne,
			Usage:    usageShow,
			MaxNArgs: 2,
			Subcommands: map[string]*command{
				"all": {
					Func:     cmdShowAll,
					Usage:    usageShow,
					MaxNArgs: 1,
				},
				"interfaces": {
					Func:  cmdShowInterfaces,
					Usage: usageShow,
				},
			},
		},
		"genkey": {
			Func:  cmdGenKey,
			Usage: "wg genkey",
		},
		"genpsk": {
			Func:  cmdGenPSK,
			Usage: "wg genpsk",
		},
		"pubkey": {
			Func:  cmdGenPubKeyFromStdin,
			Usage: "wg pubkey",
		},
	},
}

func Main(args []string) error {
	cmd := commandRoot
	for len(args) > 0 {
		if args[0] == "--help" {
			return cmd.Usage
		}

		var match *command
		for k, v := range cmd.Subcommands {
			if k == args[0] {
				match = v
				break
			}
		}
		if match != nil {
			cmd = match
			args = args[1:]
			continue
		}

		if len(args) < cmd.MinNArgs || len(args) > cmd.MaxNArgs {
			return cmd.Usage
		}

		break
	}

	return cmd.Func(args)
}
