package umb

import (
	"fmt"
	"math"
	"bytes"
	"encoding/binary"
	"errors"
)

const (

	START_FRAME = 0X01
	HEADER_VERSION = 0X10
	FROM_ID 	= 0xF001
	START_TRANSMISSION = 0X02
	REQUEST_CMD = 0X23
	REQUEST_CMD_VERC = 0X10
	END_TRANSMISSION = 0X03
	END_FRAME = 0X04

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

	IRS31_IRS21CON_UMB	= iota + 1
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

type Packet struct {
	SOH		byte
	Ver 	byte
	To 		[]byte
	From 	[]byte
	Len 	byte
	STX 	byte
	Cmd 	byte
	Verc 	byte
	Status  byte
	Payload []byte
	Typ 	byte
	Val 	[]byte
	ETX 	byte
	Cs 		[]byte
	EOT 	byte
	Id 		uint16
	Class 	uint16
	Channel uint16
	Value 	interface {}
	Message []byte
}


	// pckt := EncodeRequestPacket(1, ARS31_ARS31PRO_UMB, []uint16{151})
	// fmt.Printf("% X\n", pckt.message)
	// pckt, err = pckt.DecodeResponsePacket([]byte{0x01, 0x10, 0x01, 0xF0, 0x01, 0x40, 0x0A, 0x02, 0x23, 0x10, 0x00, 0x97, 0x00, 0x16, 0x66, 0x66, 0x96, 0xC1, 0x03, 0xFF, 0xEA, 0x04})
	// if err != nil {
	// 	fmt.Println(err.Error())
	// }
	// fmt.Printf("% X\n", pckt)

func ChangeProtocolASCIIToBinaryPacket(id, class uint16) []byte {
	var tempTo uint16 = (class) << 12 
	tempTo = tempTo | (0x0FFF & id)
	return []byte("& " + fmt.Sprint(tempTo) + " X\r")

}

func EncodeRequestPacket(id, class, channel uint16) (pckt *Packet) {

	var tempTo uint16 = (class) << 12 
	tempTo = tempTo | (0x0FFF & id)

	pckt = &Packet {
		SOH	 	: START_FRAME,
		Ver  	: HEADER_VERSION,
		To 	 	: make([]byte, 2),
		From 	: make([]byte, 2),
		Len 	: 4,
		STX  	: START_TRANSMISSION,
		Cmd  	: REQUEST_CMD,
		Verc 	: REQUEST_CMD_VERC,
		Payload : make([]byte, 2),
		ETX  	: END_TRANSMISSION,
		Cs 		: make([]byte, 2),
		EOT  	: END_FRAME,
	}
	binary.LittleEndian.PutUint16(pckt.To, tempTo)
	binary.LittleEndian.PutUint16(pckt.From, FROM_ID)
	binary.LittleEndian.PutUint16(pckt.Payload, channel)

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
	pckt.Message = append(pckt.Message, pckt.Payload[0])
	pckt.Message = append(pckt.Message, pckt.Payload[1])
	pckt.Message = append(pckt.Message, pckt.ETX)
	binary.LittleEndian.PutUint16(pckt.Cs, calcCRC(pckt.Message))
	pckt.Message = append(pckt.Message, pckt.Cs[0])
	pckt.Message = append(pckt.Message, pckt.Cs[1])
	pckt.Message = append(pckt.Message, pckt.EOT)

	return pckt
}

func (p *Packet) DecodeResponsePacket(byt []byte) (pckt *Packet, err error) {
	if byt == nil {
		err = errors.New("The packet nil.")
		return
	}
	bytLen := len(byt)
	if bytLen >= 16 && byt[0] != START_FRAME || byt[bytLen -1] != END_FRAME {
		err = errors.New("The packet cannot be resolved.")
		return
	}

	if bytLen != int(byt[6]) + 12 {
		err = errors.New("Wrong length.")
		return
	}

	if calcCRC(byt[:bytLen -3]) != binary.LittleEndian.Uint16(byt[bytLen - 3:bytLen - 1]) {
		err = errors.New("Wrong CRC.")
		return
	}

	if !bytes.Equal(p.To, byt[4:6]) || !bytes.Equal(p.From, byt[2:4]) {
		err = errors.New("ID or From error.")
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

	if !bytes.Equal(p.Payload, byt[11:11 + len(p.Payload)]) {
		err = errors.New("Wrong Channel.")
		return
	}

	if bytLen - 4 <= 12 + len(p.Payload) {
		err = errors.New("The packet cannot be resolved.")
		return
	} 

	pckt = &Packet {
		SOH	 	: byt[0],
		Ver  	: byt[1],
		To 	 	: byt[2:4],
		From 	: byt[4:6],
		Len 	: byt[6],
		STX  	: byt[7],
		Cmd  	: byt[8],
		Verc 	: byt[9],
		Status	: byt[10],
		Payload : byt[11:11 + len(p.Payload)],
		Typ 	: byt[11 + len(p.Payload)],
		Val   	: byt[12 + len(p.Payload):bytLen - 4],
		ETX  	: byt[bytLen - 4],
		Cs 		: byt[bytLen - 3:bytLen - 1],
		EOT  	: END_FRAME,
		Id 		: binary.LittleEndian.Uint16(byt[4:6]) & 0x0FFF,
		Class	: binary.LittleEndian.Uint16(byt[4:6]) >> 12,
		Channel : binary.LittleEndian.Uint16(byt[11:11 + len(p.Payload)]),
		Message : byt,
	}

	switch pckt.Typ {
	case UNSIGNED_CHAR:
		if len(pckt.Val) != 1 {
			pckt.Value = 0
		} else {
			pckt.Value = uint8(pckt.Val[0])
		}
	case SIGNED_CHAR:
		if len(pckt.Val) != 1 {
			pckt.Value = 0
		} else {
			pckt.Value = int8(pckt.Val[0])
		}
	case UNSIGNED_SHORT:
		if len(pckt.Val) != 2 {
			pckt.Value = 0
		} else {
			pckt.Value = binary.LittleEndian.Uint16(pckt.Val)
		}
	case SIGNED_SHORT:
		if len(pckt.Val) != 2 {
			pckt.Value = 0
		} else {
			pckt.Value = int16(binary.LittleEndian.Uint16(pckt.Val))
		}
	case UNSIGNED_LONG:
		if len(pckt.Val) != 4 {
			pckt.Value = 0
		} else {
			pckt.Value = binary.LittleEndian.Uint32(pckt.Val)
		}
	case SIGNED_LONG:
		if len(pckt.Val) != 4 {
			pckt.Value = 0
		} else {
			pckt.Value = int32(binary.LittleEndian.Uint32(pckt.Val))
		}
	case FLOAT:
		if len(pckt.Val) != 4 {
			pckt.Value = 0
		} else {
			pckt.Value = math.Float32frombits(binary.LittleEndian.Uint32(pckt.Val))
		}
	case DOUBLE:
		if len(pckt.Val) != 8 {
			pckt.Value = 0
		} else {
			pckt.Value = math.Float64frombits(binary.LittleEndian.Uint64(pckt.Val))
		}
	default:
		err = errors.New("Non type declared.")
		pckt.Value = 0
	}

	return
}

func calcCRC(byt []byte) uint16 {
	tempByte := make([]byte, len(byt))
	copy(tempByte, byt)
    crc := 0xFFFF
    x16 := 0x0000
    for i := 0; i < len(tempByte); i++ {
        for k := 0; k < 8; k++ {

            if (crc & 0x0001) ^ (int(tempByte[i]) & 0x01) == 1 {
                x16 = 0x8408;
            } else {
                x16 = 0x0000;
            }
            crc = crc >> 1;
            crc ^= x16;
            tempByte[i] = tempByte[i] >> 1;
        }
    }
    return uint16(crc)
}

var statusInfo []string = []string {
	"OK Command successful; no error; all OK",
	"","","","","","","","","","","","","","","",
	"UNBEK_CMD Unknown command; not supported by this device",
	"UNGLTG_PARAM Invalid parameter",
	"UNGLTG_HEADER Invalid header version",
	"UNGLTG_VERC Invalid version of the command",
	"UNGLTG_PW Invalid password for command",
	"","","","","","","","","","","",
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
	"","",
	"E2_DEFAULT_KONF Configuration error, default configuration was loaded",
	"E2_CAL_ERROR Calibration error / the calibration is invalid, measurement not possible",
	"E2_CRC_KONF_ERR CRC error on loading configuration; default configuration was loaded",
	"E2_CRC_KAL_ERR CRC error on loading calibration; measurement not possible",
	"ADJ_STEP1 Calibration Step 1",
	"ADJ_OK Calibration OK",
	"KANAL_AUS Channel deactivated",
}

const (
	STATUS_OK = 0
	UNBEK_CMD = 16
	UNGLTG_PARAM
)
