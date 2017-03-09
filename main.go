package main

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
			return Dot11Tag{}, -1, errors.New("array too short, < 2")
		}
	} else {
		return Dot11Tag{}, -1, errors.New("array too short < len")
	}
}

func IsDot11ProbeRequestPacket(inPacket, gopacket.Packet) bool {
	wlan := packet.Layer(layers.LayerTypeDot11)
	if wlan != nil {
		wlanPacket, _ := wlan.(*layers.Dot11)
		if wlanPacket.Type == 0x10 {
			return true
		}
	}
	return false
}

func GetDot11ProbeRequest(inPacket gopacket.Packet) (Dot11ProbeRequest, error) {
	return Dot11ProbeRequest{}, nil
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
		panic(fmt.Sprintf("Bad! %s", err))
	}
	defer handle.Close()

	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		wlan := packet.Layer(layers.LayerTypeDot11)
		if wlan != nil {
			wlanPacket, _ := wlan.(*layers.Dot11)
			if wlanPacket.Type == 0x10 {
				var decomposedPacket []Dot11Tag
				fmt.Println(wlanPacket.Type)
				payload := wlanPacket.LayerPayload()
				fmt.Printf("Payload: \n %#X\n", payload)
				start := 0
				fmt.Printf("Length of payload: %d\n", len(payload))
				for start < len(payload) {
					pl, rem, err := getTagAndLoad(payload[start:])
					if err == nil {
						decomposedPacket = append(decomposedPacket, pl)
						start += rem
					} else {
						fmt.Println("Something went wrong. %s\n", err)
						break // we should quit while we are ahead
					}
				}
			}
		}
	}
}
