package dhcp6

// NewInformationRequest builds an Information-Request (RFC 8415 §18.2.6)
// that asks for OPTION_ADDR_REG_ENABLE (RFC 9686) in its Option Request.
func NewInformationRequest(xid [3]byte, duid []byte) *Message {
	return &Message{
		Type: MsgInformationRequest,
		XID:  xid,
		Options: Options{
			{Code: OptClientID, Data: duid},
			{Code: OptORO, Data: []byte{byte(OptAddrRegEnable >> 8), byte(OptAddrRegEnable)}},
			{Code: OptElapsedTime, Data: []byte{0, 0}},
		},
	}
}
