package creepy

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/op/go-logging"
)

import "errors"
import "fmt"
import "flag"

var log = logging.MustGetLogger("creepypacket")
var format = logging.MustStringFormatter(
	`%{color}%{time:15:04:05.000} %{shortfunc} ▶ %{level:.8s} %{id:03x}%{color:reset} %{message}`,
)

var (
	pcapFile string
	handle   *pcap.Handle
	err      error
)

type Dot11Tag struct {
	Type    int
	Length  int
	Payload []byte
}

type Dot11ProbeRequest struct {
	Tags []Dot11Tag
}

func getTagAndLoad(inData []byte) (Dot11Tag, int, error) {
	if len(inData) >= 2 {
		tag := int(inData[0])
		length := int(inData[1])
		if len(inData) > length {
			payload := inData[2 : 2+length]
			return Dot11Tag{Type: tag, Length: length, Payload: payload}, length + 2, nil
		} else {
			return Dot11Tag{}, -1, errors.New(fmt.Sprintf("array too short, tried %d but len is %d", length+2, len(inData)))
		}
	} else {
		return Dot11Tag{}, -1, errors.New("array too short < 2")
	}
}

func IsDot11ProbeRequestPacket(inPacket gopacket.Packet) bool {
	wlanPacket, _ := GetDecodedWLAN(inPacket)
	if wlanPacket.Type == 0x10 {
		return true
	}
	return false
}

func GetDecodedWLAN(packet gopacket.Packet) (*layers.Dot11, error) {
	wlan := packet.Layer(layers.LayerTypeDot11)
	if wlan != nil {
		decoded, _ := wlan.(*layers.Dot11)
		return decoded, nil
	} else {
		return nil, errors.New("No 802.11 Packet present.")
	}
}

func IsWLANPacket(packet gopacket.Packet) bool {
	if packet.Layer(layers.LayerTypeDot11) != nil {
		return true
	} else {
		return false
	}
}

func StringInArray(strArray []string, searchString string) bool {
	// Kind of hurts my soul to write this function, there must be a better way.
	for _, v := range strArray {
		if v == searchString {
			return true
		}
	}
	return false
}

func GetDot11ProbeRequest(inPacket gopacket.Packet) (Dot11ProbeRequest, error) {
	wlanPacket, _ := GetDecodedWLAN(inPacket)
	payload := wlanPacket.LayerPayload()
	start := 0
	var decomposedPacket []Dot11Tag
	for start < len(payload) {
		pl, rem, err := getTagAndLoad(payload[start:])
		if err == nil {
			decomposedPacket = append(decomposedPacket, pl)
			start += rem
		} else {
			log.Debug("Malformed packet.")
			// This is probably a malformed packet.
			break // we should quit while we are ahead
		}
	}
	return Dot11ProbeRequest{Tags: decomposedPacket}, nil
}

func main() {
	// Set the logs
	logging.SetFormatter(format)

	// load the file
	var filename = flag.String("filename", "", "input filename")
	flag.Parse()
	pcapFile = *filename

	// Open file instead of device
	handle, err = pcap.OpenOffline(pcapFile)
	if err != nil {
		msg := fmt.Sprintf("Bad! %s", err)
		log.Critical(msg)
		panic(msg)
	}
	defer handle.Close()

	var userMap = make(map[string][]string)
	var macAddress string = " " // must be a better way to deal with this?

	// Scan all the packets...
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if IsWLANPacket(packet) {
			decodedWLAN, err := GetDecodedWLAN(packet)
			if err == nil {
				macAddress = fmt.Sprintf("%s", decodedWLAN.Address2)
			} else {
				macAddress = " "
			}

			if IsDot11ProbeRequestPacket(packet) {
				packetData, err := GetDot11ProbeRequest(packet)
				if err != nil {
					continue
				}
				for _, element := range packetData.Tags {
					// loop here, refactor guts?
					if element.Type == 0 && element.Length > 0 {
						if macAddress != " " && userMap[macAddress] == nil {
							userMap[macAddress] = []string{string(element.Payload)}
						} else {
							if !StringInArray(userMap[macAddress], string(element.Payload)) {
								userMap[macAddress] = append(userMap[macAddress], string(element.Payload))
							}
						}
					}
				}
			}
		}
	}

	for k, v := range userMap {
		fmt.Printf("%s %s\n", k, v)
	}
}
