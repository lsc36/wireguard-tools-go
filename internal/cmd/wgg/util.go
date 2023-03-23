package wgg

import (
	"bytes"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func keyIsZero(key wgtypes.Key) bool {
	var zeroKey [wgtypes.KeyLen]byte
	return bytes.Equal(key[:], zeroKey[:])
}
