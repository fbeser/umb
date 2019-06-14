package umb

import (
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
	Channel uint16
	Unit    String
	Typ     byte
	Value   interface{}
	Err     error
}

func ChangeProtocolASCIIToBinaryPacket(id, class uint16) []byte {
	var tempTo uint16 = (class) << 12
	tempTo = tempTo | (0x0FFF & id)
	return []byte(fmt.Sprintf("& %d X\r", tempTo))

}

func BinaryOnlineDataRequest(id, class uint16, channel []uint16) (message [][]byte) {

	channelLen := len(channel)

	if channelLen == 0 {
		return
	}

	channelLimit := 100

	if channelLen > channelLimit {
		messageCount := channelLen / channelLimit
		for i := 0; i < messageCount; i++ {
			if msg := BinaryOnlineDataRequest(id, class, channel[i*channelLimit:(i+1)*channelLimit]); msg != nil && len(msg) > 0 {
				message = append(message, msg[0])
			}
		}
		if msg := BinaryOnlineDataRequest(id, class, channel[(channelLen/channelLimit)*channelLimit:channelLen]); msg != nil && len(msg) > 0 {
			message = append(message, msg[0])
		}
		return
	}

	class = (class) << 12
	class = class | (0x0FFF & id)
	tempTo := make([]byte, 2)
	binary.LittleEndian.PutUint16(tempTo, class)
	tempFrom := make([]byte, 2)
	binary.LittleEndian.PutUint16(tempFrom, FROM_ID)

	message = append(message, []byte{})

	message[0] = append(message[0], START_FRAME)
	message[0] = append(message[0], HEADER_VERSION)
	message[0] = append(message[0], tempTo[0])
	message[0] = append(message[0], tempTo[1])
	message[0] = append(message[0], tempFrom[0])
	message[0] = append(message[0], tempFrom[1])
	message[0] = append(message[0], byte(channelLen*2+3))
	message[0] = append(message[0], START_TRANSMISSION)
	message[0] = append(message[0], MULTI_ONLINE_DATA_REQUEST_CMD)
	message[0] = append(message[0], MULTI_ONLINE_DATA_REQUEST_CMD_VERC)
	message[0] = append(message[0], byte(channelLen))
	for i := 0; i < channelLen; i++ {
		tempChannel := make([]byte, 2)
		binary.LittleEndian.PutUint16(tempChannel, channel[i])
		message[0] = append(message[0], tempChannel[0])
		message[0] = append(message[0], tempChannel[1])
	}
	message[0] = append(message[0], END_TRANSMISSION)
	tempCrc := make([]byte, 2)
	binary.LittleEndian.PutUint16(tempCrc, CalcCRC(message[0]))
	message[0] = append(message[0], tempCrc[0])
	message[0] = append(message[0], tempCrc[1])
	message[0] = append(message[0], END_FRAME)

	return
}

func BinaryOnlineDataResponse(byt []byte) (id, class uint16, pckt []BinaryDataPacket, err error) {

	bytLen := len(byt)

	if bytLen < 2 {
		err = errors.New("This packet is empty.")
		return
	}

	if byt[0] != START_FRAME || byt[bytLen-1] != END_FRAME {
		err = errors.New("The packet cannot be resolved.")
		return
	}

	if bytLen != int(byt[6])+12 {
		err = errors.New("Wrong length.")
		return
	}

	if CalcCRC(byt[:bytLen-3]) != binary.LittleEndian.Uint16(byt[bytLen-3:bytLen-1]) {
		err = errors.New("Wrong CRC.")
		return
	}

	if byt[10] != 0 {
		if int(byt[10]) > len(statusInfo) {
			err = errors.New("Status error :" + fmt.Sprint(byt[10]))
			return
		}
		err = errors.New(statusInfo[byt[10]])
		return
	}

	if byt[8] == ONLINE_DATA_REQUEST_CMD && byt[9] == ONLINE_DATA_REQUEST_CMD_VERC {
		pckt = append(pckt, BinaryDataPacket{})
		if 14 > bytLen {
			pckt[0].Err = errors.New("Wrong length.")
		}
		pckt[0].Channel = binary.LittleEndian.Uint16(byt[11:13])
		pckt[0].Typ = byt[13]
		pckt[0].Value, pckt[0].Err = detectTypeConvert(byt[13], byt[14:bytLen-4])
		return
	}

	if byt[8] == MULTI_ONLINE_DATA_REQUEST_CMD && byt[9] == MULTI_ONLINE_DATA_REQUEST_CMD_VERC {

		id = binary.LittleEndian.Uint16(byt[4:6]) & 0x0FFF
		class = binary.LittleEndian.Uint16(byt[4:6]) >> 12

		next := 12
		for channelCount := 0; next < bytLen-5; channelCount++ {
			fmt.Println(next, bytLen)

			pckt = append(pckt, BinaryDataPacket{})

			if byt[next+1] != 0 {
				if int(byt[next+1]) > len(statusInfo) {
					pckt[channelCount].Err = errors.New("Status error :" + fmt.Sprint(byt[next+1]))
					next += int(byt[next]) + 1
					continue
				}
				fmt.Println(byt[next+1])
				pckt[channelCount].Err = errors.New(statusInfo[byt[next+1]])
				next += int(byt[next]) + 1
				continue
			}

			pckt[channelCount].Channel = binary.LittleEndian.Uint16(byt[next+2 : next+4])
			pckt[channelCount].Typ = byt[next+4]
			pckt[channelCount].Value, pckt[channelCount].Err = detectTypeConvert(byt[next+4], byt[next+5:next+int(byt[next])+1])

			if byt[next] == 0 {
				break
			}
			next += int(byt[next]) + 1
		}

		return
	}

	err = errors.New("Unknown command or version")
	return

}

func detectTypeConvert(typ byte, val []byte) (value interface{}, err error) {
	switch typ {
	case UNSIGNED_CHAR:
		if len(val) != 1 {
			value = uint8(0)
		} else {
			value = uint8(val[0])
		}
	case SIGNED_CHAR:
		if len(val) != 1 {
			value = int8(0)
		} else {
			value = int8(val[0])
		}
	case UNSIGNED_SHORT:
		if len(val) != 2 {
			value = uint16(0)
		} else {
			value = binary.LittleEndian.Uint16(val)
		}
	case SIGNED_SHORT:
		if len(val) != 2 {
			value = int16(0)
		} else {
			value = int16(binary.LittleEndian.Uint16(val))
		}
	case UNSIGNED_LONG:
		if len(val) != 4 {
			value = uint32(0)
		} else {
			value = binary.LittleEndian.Uint32(val)
		}
	case SIGNED_LONG:
		if len(val) != 4 {
			value = int32(0)
		} else {
			value = int32(binary.LittleEndian.Uint32(val))
		}
	case FLOAT:
		if len(val) != 4 {
			value = float32(0)
		} else {
			value = math.Float32frombits(binary.LittleEndian.Uint32(val))
		}
	case DOUBLE:
		if len(val) != 8 {
			value = float64(0)
		} else {
			value = math.Float64frombits(binary.LittleEndian.Uint64(val))
		}
	default:
		err = errors.New("Non type declared.")
		value = 0
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
