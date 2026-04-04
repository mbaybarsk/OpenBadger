//go:build !linux

package pcap

import (
	"fmt"

	"github.com/google/gopacket"
)

func openLiveSource(SourceConfig) (packetSource, error) {
	return nil, fmt.Errorf("live pcap capture is only supported on linux")
}

func isTimeoutError(error) bool {
	return false
}

func extractAncillaryVLANs(gopacket.CaptureInfo) []int {
	return nil
}
