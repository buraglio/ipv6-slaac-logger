package dhcp6

import "crypto/rand"

// NewAddrRegInform builds an RFC 9686 ADDR-REG-INFORM carrying a Client ID and
// exactly one IA Address, followed by any extra options (Vendor Class, FQDN).
func NewAddrRegInform(xid [3]byte, duid []byte, ia IAAddress, extra ...Option) (*Message, error) {
	iaData, err := ia.Marshal()
	if err != nil {
		return nil, err
	}
	opts := Options{{Code: OptClientID, Data: duid}, {Code: OptIAAddr, Data: iaData}}
	opts = append(opts, extra...)
	return &Message{Type: MsgAddrRegInform, XID: xid, Options: opts}, nil
}

// RandomXID returns a random 24-bit transaction ID.
func RandomXID() ([3]byte, error) {
	var x [3]byte
	_, err := rand.Read(x[:])
	return x, err
}
