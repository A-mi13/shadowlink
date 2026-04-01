package wbcreds

import "strings"

// pbVar decodes a protobuf varint from d, returning the value and bytes consumed.
func pbVar(d []byte) (uint64, int) {
	var val uint64
	for i := 0; i < len(d); i++ {
		val |= uint64(d[i]&0x7F) << (7 * i)
		if d[i]&0x80 == 0 {
			return val, i + 1
		}
	}
	return val, len(d)
}

// pbAll extracts all length-delimited fields matching fieldNum from a protobuf message.
func pbAll(d []byte, fieldNum int) [][]byte {
	var result [][]byte
	pos := 0
	for pos < len(d) {
		tag, n := pbVar(d[pos:])
		if n == 0 {
			break
		}
		pos += n
		fnum := int(tag >> 3)
		wtype := tag & 0x07

		switch wtype {
		case 0: // varint
			_, n = pbVar(d[pos:])
			pos += n
		case 1: // 64-bit fixed
			pos += 8
		case 2: // length-delimited
			ln, n := pbVar(d[pos:])
			pos += n
			length := int(ln)
			if pos+length > len(d) {
				return result
			}
			if fnum == fieldNum {
				result = append(result, d[pos:pos+length])
			}
			pos += length
		case 5: // 32-bit fixed
			pos += 4
		default:
			return result
		}
	}
	return result
}

// pbStr returns the first length-delimited field matching fieldNum as a string.
func pbStr(d []byte, fieldNum int) string {
	fields := pbAll(d, fieldNum)
	if len(fields) == 0 {
		return ""
	}
	return string(fields[0])
}

// PbICE extracts TURN/STUN credentials from a LiveKit protobuf WebSocket message.
//
// LiveKit SignalResponse structure:
//   SignalResponse { JoinResponse join = 1; ... }
//   JoinResponse { ... repeated ICEServer ice_servers = 5; ... }
//   ICEServer { repeated string urls = 1; string username = 2; string credential = 3; }
//
// Path: msg[field 1 = JoinResponse][field 5 = ice_servers][fields 1,2,3]
func PbICE(msg []byte) []TurnCred {
	var creds []TurnCred

	// Strategy: try multiple nesting paths to find ICE servers.
	// LiveKit wraps everything in SignalResponse — JoinResponse is field 1.
	sources := [][]byte{msg}

	// Unwrap field 1 (JoinResponse) from SignalResponse
	for _, joinResp := range pbAll(msg, 1) {
		sources = append(sources, joinResp)
	}

	for _, src := range sources {
		// ICE servers can be at field 5 (standard) or field 9 (alternative)
		for _, iceField := range []int{5, 9} {
			for _, ice := range pbAll(src, iceField) {
				creds = append(creds, extractICEServer(ice)...)

				// ICE servers may be further nested in field 1
				for _, nested := range pbAll(ice, 1) {
					creds = append(creds, extractICEServer(nested)...)
				}
			}
		}
	}

	return creds
}

// extractICEServer extracts TURN credentials from a single ICEServer protobuf message.
// ICEServer { repeated string urls = 1; string username = 2; string credential = 3; }
func extractICEServer(data []byte) []TurnCred {
	var creds []TurnCred

	// Field 1 can be repeated (multiple URLs per ICE server)
	urls := pbAll(data, 1)
	user := pbStr(data, 2)
	pass := pbStr(data, 3)

	for _, urlBytes := range urls {
		url := string(urlBytes)
		if strings.HasPrefix(url, "turn") || strings.HasPrefix(url, "stun") {
			creds = append(creds, TurnCred{
				URL:      url,
				Username: user,
				Password: pass,
			})
		}
	}

	return creds
}
