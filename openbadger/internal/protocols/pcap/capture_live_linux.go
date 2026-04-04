//go:build linux

package pcap

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
)

type liveSource struct {
	handle *afpacket.TPacket
}

func (s *liveSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return s.handle.ReadPacketData()
}

func (s *liveSource) LinkType() layers.LinkType {
	return layers.LinkTypeEthernet
}

func (s *liveSource) Close() {
	if s != nil && s.handle != nil {
		s.handle.Close()
	}
}

func openLiveSource(cfg SourceConfig) (packetSource, error) {
	device := cfg.Interface
	readTimeout := cfg.ReadTimeout
	if readTimeout <= 0 {
		readTimeout = defaultReadTimeout
	}
	if readTimeout < time.Millisecond {
		readTimeout = time.Millisecond
	}

	handle, err := afpacket.NewTPacket(
		afpacket.OptInterface(device),
		afpacket.OptPollTimeout(readTimeout),
	)
	if err != nil {
		return nil, fmt.Errorf("open live pcap interface: %w", err)
	}

	return &liveSource{handle: handle}, nil
}

func isTimeoutError(err error) bool {
	return errors.Is(err, afpacket.ErrTimeout)
}

func extractAncillaryVLANs(captureInfo gopacket.CaptureInfo) []int {
	var vlanIDs []int
	for _, value := range captureInfo.AncillaryData {
		vlan, ok := value.(afpacket.AncillaryVLAN)
		if !ok {
			continue
		}
		vlanIDs = append(vlanIDs, vlan.VLAN)
	}

	return uniqueSortedInts(vlanIDs)
}
