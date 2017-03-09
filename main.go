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
			return Dot11Tag{}, -1, errors.New(fmt.Sprintf("array too short, tried %d but len is %d", length+2, len(inData)))
		}
	} else {
		return Dot11Tag{}, -1, errors.New("array too short < 2")
	}
}

func IsDot11ProbeRequestPacket(inPacket gopacket.Packet) bool {
	wlan := inPacket.Layer(layers.LayerTypeDot11)
	if wlan != nil {
		wlanPacket, _ := wlan.(*layers.Dot11)
		if wlanPacket.Type == 0x10 {
			return true
		}
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

func GetDot11ProbeRequest(inPacket gopacket.Packet) (Dot11ProbeRequest, error) {
	wlanPacket, _ := inPacket.Layer(layers.LayerTypeDot11).(*layers.Dot11)
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

	// Loop through packets in file and analyze away!

	/*
		Now we need:
		- A map of users by MAC
		- Each user has a list of unique SSIDs
	*/

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// fmt.Println(packet.Dump())
		// fmt.Println(gopacket.LayerString(packet.Layer(layers.LayerTypeDot11)))
		/*
			wlan := packet.Layer(layers.LayerTypeDot11)
			wlanPacket, _ := wlan.(*layers.Dot11)
			fmt.Printf("%s", wlanPacket.Address2) */
		if IsWLANPacket(packet) {
			decodedWLAN, err := GetDecodedWLAN(packet)
			if err == nil {
				fmt.Printf("MAC: %s\n", decodedWLAN.Address2)
			}
		}

		if IsDot11ProbeRequestPacket(packet) {
			packetData, err := GetDot11ProbeRequest(packet)
			if err == nil {
				for _, element := range packetData.Tags {
					if element.Type == 0 && element.Length > 0 {
						fmt.Printf("SSID: %s\n", element.Payload)
					}
				}
			}
		}
	}
}
