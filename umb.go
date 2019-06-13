package umb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

const (
	START_FRAME                        = 0X01
	HEADER_VERSION                     = 0X10
	FROM_ID                            = 0xF001
	START_TRANSMISSION                 = 0X02
	ONLINE_DATA_REQUEST_CMD            = 0X23
	ONLINE_DATA_REQUEST_CMD_VERC       = 0X10
	MULTI_ONLINE_DATA_REQUEST_CMD      = 0X2F
	MULTI_ONLINE_DATA_REQUEST_CMD_VERC = 0X10
	END_TRANSMISSION                   = 0X03
	END_FRAME                          = 0X04
)

///////////////////DATA TYPES///////////////////
const (
	UNSIGNED_CHAR = iota + 0x10
	SIGNED_CHAR
	UNSIGNED_SHORT
	SIGNED_SHORT
	UNSIGNED_LONG
	SIGNED_LONG
	FLOAT
	DOUBLE
)

const (
	IRS31_IRS21CON_UMB = iota + 1
	R2S_UMB
	VS20_VS2K_VS25K_UMB
	ARS31_ARS31PRO_UMB
	NIRS31_UMB
	ANACON_UMB
	WSx_UMB
	VENTUS_V200A_UMB
	IRS31PRO_UMB
	MARWIS_UMB
	SHM50_UMB
	_12
	UNICON_UMB
	_14
	DACON8_UMB
)

type BinaryOnlineDataPacket struct {
	SOH     byte
	Ver     byte
	To      []byte
	From    []byte
	Len     byte
	STX     byte
	Cmd     byte
	Verc    byte
	Status  byte
	Packet  []BinaryDataPacket
	ETX     byte
	Cs      []byte
	EOT     byte
	Id      uint16
	Class   uint16
	Message []byte
}

type BinaryDataPacket struct {
	Len     byte
	Status  byte
	Channel uint16
	Payload []byte
	Typ     byte
	Val     []byte
	Value   interface{}
}

func ChangeProtocolASCIIToBinaryPacket(id, class uint16) []byte {
	var tempTo uint16 = (class) << 12
	tempTo = tempTo | (0x0FFF & id)
	return []byte(fmt.Sprintf("& %d X\r", tempTo))

}

func NewBinaryPacket() *BinaryOnlineDataPacket {
	return &BinaryOnlineDataPacket{}
}

func (pckt *BinaryOnlineDataPacket) Pack(id, class uint16, channel []uint16) {

	if len(channel) == 0 {
		return
	}

	pckt.Id = id
	pckt.Class = class

	var tempTo uint16 = (class) << 12
	tempTo = tempTo | (0x0FFF & id)

	pckt.SOH = START_FRAME
	pckt.Ver = HEADER_VERSION
	pckt.To = make([]byte, 2)
	pckt.From = make([]byte, 2)
	pckt.Len = 2 + byte(len(channel)*2)
	pckt.STX = START_TRANSMISSION
	if len(channel) > 1 {
		pckt.Len++
		pckt.Cmd = MULTI_ONLINE_DATA_REQUEST_CMD
		pckt.Verc = MULTI_ONLINE_DATA_REQUEST_CMD_VERC
	} else {
		pckt.Cmd = ONLINE_DATA_REQUEST_CMD
		pckt.Verc = ONLINE_DATA_REQUEST_CMD_VERC
	}
	pckt.Packet = make([]BinaryDataPacket, len(channel))
	pckt.ETX = END_TRANSMISSION
	pckt.Cs = make([]byte, 2)
	pckt.EOT = END_FRAME

	binary.LittleEndian.PutUint16(pckt.To, tempTo)
	binary.LittleEndian.PutUint16(pckt.From, FROM_ID)
	for i := 0; i < len(channel); i++ {
		pckt.Packet[i].Payload = make([]byte, 2)
		binary.LittleEndian.PutUint16(pckt.Packet[i].Payload, channel[i])
	}

	pckt.Message = append(pckt.Message, pckt.SOH)
	pckt.Message = append(pckt.Message, pckt.Ver)
	pckt.Message = append(pckt.Message, pckt.To[0])
	pckt.Message = append(pckt.Message, pckt.To[1])
	pckt.Message = append(pckt.Message, pckt.From[0])
	pckt.Message = append(pckt.Message, pckt.From[1])
	pckt.Message = append(pckt.Message, pckt.Len)
	pckt.Message = append(pckt.Message, pckt.STX)
	pckt.Message = append(pckt.Message, pckt.Cmd)
	pckt.Message = append(pckt.Message, pckt.Verc)
	if len(pckt.Packet) > 1 {
		pckt.Message = append(pckt.Message, byte(len(pckt.Packet)))
	}
	for i := 0; i < len(pckt.Packet); i++ {
		pckt.Message = append(pckt.Message, pckt.Packet[i].Payload[0])
		pckt.Message = append(pckt.Message, pckt.Packet[i].Payload[1])
	}
	pckt.Message = append(pckt.Message, pckt.ETX)
	binary.LittleEndian.PutUint16(pckt.Cs, CalcCRC(pckt.Message))
	pckt.Message = append(pckt.Message, pckt.Cs[0])
	pckt.Message = append(pckt.Message, pckt.Cs[1])
	pckt.Message = append(pckt.Message, pckt.EOT)

}

func (p *BinaryOnlineDataPacket) Unpack(byt []byte) (pckt *BinaryOnlineDataPacket, generalError error, err []error) {

	bytLen := len(byt)

	if bytLen < 2 {
		generalError = errors.New("This packet is empty.")
		return
	}

	if byt[0] != START_FRAME || byt[bytLen-1] != END_FRAME {
		generalError = errors.New("The packet cannot be resolved.")
		return
	}

	if bytLen != int(byt[6])+12 {
		generalError = errors.New("Wrong length.")
		return
	}

	if CalcCRC(byt[:bytLen-3]) != binary.LittleEndian.Uint16(byt[bytLen-3:bytLen-1]) {
		generalError = errors.New("Wrong CRC.")
		return
	}

	if !bytes.Equal(p.To, byt[4:6]) || !bytes.Equal(p.From, byt[2:4]) {
		generalError = errors.New("ID or From error.")
		return
	}

	if p.Cmd != byt[8] {
		generalError = errors.New("Wrong Command.")
		return
	}

	if byt[10] != 0 {
		if int(byt[10]) > len(statusInfo) {
			generalError = errors.New("Status error :" + fmt.Sprint(byt[10]))
			return
		}
		generalError = errors.New(statusInfo[byt[10]])
		return
	}

	pckt = &BinaryOnlineDataPacket{
		SOH:     byt[0],
		Ver:     byt[1],
		To:      byt[2:4],
		From:    byt[4:6],
		Len:     byt[6],
		STX:     byt[7],
		Cmd:     byt[8],
		Verc:    byt[9],
		Status:  byt[10],
		Packet:  make([]BinaryDataPacket, len(p.Packet)),
		ETX:     byt[bytLen-4],
		Cs:      byt[bytLen-3 : bytLen-1],
		EOT:     END_FRAME,
		Id:      binary.LittleEndian.Uint16(byt[4:6]) & 0x0FFF,
		Class:   binary.LittleEndian.Uint16(byt[4:6]) >> 12,
		Message: byt,
	}

	err = make([]error, len(pckt.Packet))

	if len(pckt.Packet) > 1 {

		if len(pckt.Packet) != int(byt[11]) {
			generalError = errors.New("Wrong Channel Count.")
			return
		}

		next := 12

		for i := 0; i < len(pckt.Packet); i++ {
			if i != 0 {
				next += int(byt[next]) + 1
			}

			if 12+int(byt[next]) > bytLen {
				err[i] = errors.New("Wrong length.")
				return
			}

			pckt.Packet[i].Len = byt[next]

			pckt.Packet[i].Status = byt[next+1]
			if pckt.Packet[i].Status != 0 {
				if int(pckt.Packet[i].Status) > len(statusInfo) {
					err[i] = errors.New("Status error :" + fmt.Sprint(pckt.Packet[i].Status))
					continue
				}
				generalError = errors.New(statusInfo[byt[next+1]])
				continue
			}

			pckt.Packet[i].Payload = byt[next+2 : next+4]
			pckt.Packet[i].Channel = binary.LittleEndian.Uint16(pckt.Packet[i].Payload)
			if p.Packet[i].Payload[0] != pckt.Packet[i].Payload[0] || p.Packet[i].Payload[1] != pckt.Packet[i].Payload[1] {
				err[i] = errors.New("Wrong Channel.")
				continue
			}

			pckt.Packet[i].Typ = byt[next+4]
			pckt.Packet[i].Val = byt[next+5 : next+int(byt[next])+1]
		}

	} else if len(p.Packet) == 1 {
		if 14 > bytLen {
			err[0] = errors.New("Wrong length.")
		}
		pckt.Packet[0].Len = pckt.Len
		pckt.Packet[0].Status = pckt.Status
		pckt.Packet[0].Payload = byt[11:13]
		pckt.Packet[0].Channel = binary.LittleEndian.Uint16(pckt.Packet[0].Payload)
		pckt.Packet[0].Typ = byt[13]
		pckt.Packet[0].Val = byt[14 : bytLen-4]
	}

	for i := 0; i < len(pckt.Packet); i++ {

		switch pckt.Packet[i].Typ {
		case UNSIGNED_CHAR:
			if len(pckt.Packet[i].Val) != 1 {
				pckt.Packet[i].Value = uint8(0)
			} else {
				pckt.Packet[i].Value = uint8(pckt.Packet[i].Val[0])
			}
		case SIGNED_CHAR:
			if len(pckt.Packet[i].Val) != 1 {
				pckt.Packet[i].Value = int8(0)
			} else {
				pckt.Packet[i].Value = int8(pckt.Packet[i].Val[0])
			}
		case UNSIGNED_SHORT:
			if len(pckt.Packet[i].Val) != 2 {
				pckt.Packet[i].Value = uint16(0)
			} else {
				pckt.Packet[i].Value = binary.LittleEndian.Uint16(pckt.Packet[i].Val)
			}
		case SIGNED_SHORT:
			if len(pckt.Packet[i].Val) != 2 {
				pckt.Packet[i].Value = int16(0)
			} else {
				pckt.Packet[i].Value = int16(binary.LittleEndian.Uint16(pckt.Packet[i].Val))
			}
		case UNSIGNED_LONG:
			if len(pckt.Packet[i].Val) != 4 {
				pckt.Packet[i].Value = uint32(0)
			} else {
				pckt.Packet[i].Value = binary.LittleEndian.Uint32(pckt.Packet[i].Val)
			}
		case SIGNED_LONG:
			if len(pckt.Packet[i].Val) != 4 {
				pckt.Packet[i].Value = int32(0)
			} else {
				pckt.Packet[i].Value = int32(binary.LittleEndian.Uint32(pckt.Packet[i].Val))
			}
		case FLOAT:
			if len(pckt.Packet[i].Val) != 4 {
				pckt.Packet[i].Value = float32(0)
			} else {
				pckt.Packet[i].Value = math.Float32frombits(binary.LittleEndian.Uint32(pckt.Packet[i].Val))
			}
		case DOUBLE:
			if len(pckt.Packet[i].Val) != 8 {

				pckt.Packet[i].Value = float64(0)
			} else {
				pckt.Packet[i].Value = math.Float64frombits(binary.LittleEndian.Uint64(pckt.Packet[i].Val))
			}
		default:
			err[i] = errors.New("Non type declared.")
			pckt.Packet[i].Value = 0
		}
	}

	return
}

func CalcCRC(byt []byte) uint16 {
	tempByte := make([]byte, len(byt))
	copy(tempByte, byt)
	crc := 0xFFFF
	x16 := 0x0000
	for i := 0; i < len(tempByte); i++ {
		for k := 0; k < 8; k++ {

			if (crc&0x0001)^(int(tempByte[i])&0x01) == 1 {
				x16 = 0x8408
			} else {
				x16 = 0x0000
			}
			crc = crc >> 1
			crc ^= x16
			tempByte[i] = tempByte[i] >> 1
		}
	}
	return uint16(crc)
}

var statusInfo []string = []string{
	"OK Command successful; no error; all OK",
	"", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
	"UNBEK_CMD Unknown command; not supported by this device",
	"UNGLTG_PARAM Invalid parameter",
	"UNGLTG_HEADER Invalid header version",
	"UNGLTG_VERC Invalid version of the command",
	"UNGLTG_PW Invalid password for command",
	"", "", "", "", "", "", "", "", "", "", "",
	"LESE_ERR Read error",
	"SCHREIB_ERR Write error",
	"ZU_LANG Length too great; max. permissible length is designated in <maxlength>",
	"UNGLTG_ADRESS Invalid address / storage location",
	"UNGLTG_KANAL Invalid channel",
	"UNGLTG_CMD Command not possible in this mode",
	"UNBEK_CAL_CMD Unknown calibration command",
	"CAL_ERROR Calibration error",
	"BUSY Device not ready; e.g. initialisation / calibration running",
	"LOW_VOLTAGE Undervoltage",
	"HW_ERROR Hardware error",
	"MEAS_ERROR Measurement error",
	"INIT_ERROR Error on device initialization",
	"OS_ERROR Error in operating system",
	"", "",
	"E2_DEFAULT_KONF Configuration error, default configuration was loaded",
	"E2_CAL_ERROR Calibration error / the calibration is invalid, measurement not possible",
	"E2_CRC_KONF_ERR CRC error on loading configuration; default configuration was loaded",
	"E2_CRC_KAL_ERR CRC error on loading calibration; measurement not possible",
	"ADJ_STEP1 Calibration Step 1",
	"ADJ_OK Calibration OK",
	"KANAL_AUS Channel deactivated",
	"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
	"VALUE_OVERFLOW Measurement variable (+offset) lies outside the set presentation range",
	"VALUE_UNDERFLOWMeasurement variable (+offset) lies outside the set presentation range",
	"CHANNEL_OVERRANGE Measurement value (physical) lies outside the measurement range (e.g. ADC overrange)",
	"CHANNEL_UNDERRANGE Measurement value (physical) lies outside the measurement range (e.g. ADC overrange)",
	"DATA_ERROR Data error in measurement data or no valid data available",
	"MEAS_UNABLE Device / sensor is unable to execute valid measurement due to ambient conditions",
	"", "", "", "", "", "", "", "", "", "",
	"FLASH_CRC_ERR CRC-Fehler in den Flash-Daten",
	"FLASH_WRITE_ERR Fehler beim Schreiben ins Flash; z.B. Speicherstelle nicht gelöscht",
	"FLASH_FLOAT_ERR Flash enthält ungültige Float-Werte",
}
