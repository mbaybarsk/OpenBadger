package snmp

import (
	"testing"
	"time"
)

func TestNormalizeObservations(t *testing.T) {
	t.Parallel()

	results, err := NormalizeObservations(NormalizeContext{
		SiteID:            "site-1",
		JobID:             "job-1",
		NodeKind:          "collector",
		NodeID:            "node-1",
		NodeName:          "collector-1",
		Version:           "0.1.0",
		TargetInput:       "192.0.2.10",
		TargetIP:          "192.0.2.10",
		Port:              161,
		ObservedAt:        mustTime(t, "2026-04-04T12:00:00Z"),
		CredentialProfile: "snmp-v2c-default",
	}, Result{
		System: SystemData{
			SysName:     "SW-CORE-01",
			SysDescr:    "Cisco IOS XE Software, Version 17.9.3",
			SysObjectID: "1.3.6.1.4.1.9.1.2695",
			UptimeTicks: 123456789,
			EngineID:    "8000000903001122334455",
		},
		Interfaces: []InterfaceData{{
			Index:       10101,
			Name:        "Gi1/0/1",
			Alias:       "User Access Port",
			Description: "GigabitEthernet1/0/1",
			AdminStatus: "up",
			OperStatus:  "up",
			SpeedBPS:    1000000000,
			MACAddress:  "00-11-22-33-44-66",
		}},
		ARPEntries: []ARPEntry{{
			InterfaceIndex: 12,
			ObservedIP:     "192.0.2.55",
			ObservedMAC:    "aa-bb-cc-dd-ee-ff",
		}},
		FDBEntries: []FDBEntry{{
			BridgePort:     17,
			InterfaceIndex: 10101,
			ObservedMAC:    "de-ad-be-ef-10-20",
			VLANID:         20,
		}},
	})
	if err != nil {
		t.Fatalf("NormalizeObservations returned error: %v", err)
	}

	if len(results) != 4 {
		t.Fatalf("len(results) = %d, want %d", len(results), 4)
	}

	if results[0].Type != "snmp.system" {
		t.Fatalf("results[0].Type = %q, want %q", results[0].Type, "snmp.system")
	}

	if results[0].Identifiers == nil || len(results[0].Identifiers.Hostnames) != 1 || results[0].Identifiers.Hostnames[0] != "sw-core-01" {
		t.Fatalf("results[0].Identifiers = %#v, want normalized hostname", results[0].Identifiers)
	}

	if got := results[0].Facts["vendor"]; got != "Cisco" {
		t.Fatalf("results[0].Facts[vendor] = %#v, want %q", got, "Cisco")
	}

	if got := results[1].Facts["mac_address"]; got != "00:11:22:33:44:66" {
		t.Fatalf("results[1].Facts[mac_address] = %#v, want canonical mac", got)
	}

	if results[2].Type != "snmp.arp_entry" || results[3].Type != "snmp.fdb_entry" {
		t.Fatalf("relationship types = [%q %q], want snmp.arp_entry/snmp.fdb_entry", results[2].Type, results[3].Type)
	}
}

func TestLookupDeviceInfo(t *testing.T) {
	t.Parallel()

	info := LookupDeviceInfo("1.3.6.1.4.1.9.1.2695", "Cisco IOS XE Software, Version 17.9.3")
	if info.Vendor != "Cisco" || info.Model != "C9300" || info.OSName != "IOS-XE" || info.OSVersion != "17.9.3" {
		t.Fatalf("LookupDeviceInfo() = %#v, want Cisco C9300 IOS-XE 17.9.3", info)
	}
}

func TestOIDParsingHelpers(t *testing.T) {
	t.Parallel()

	ifIndex, ip, err := parseARPEntryOID(oidARPPhysAddress, oidARPPhysAddress+".12.192.0.2.55")
	if err != nil {
		t.Fatalf("parseARPEntryOID returned error: %v", err)
	}
	if ifIndex != 12 || ip != "192.0.2.55" {
		t.Fatalf("parseARPEntryOID = (%d, %q), want (12, %q)", ifIndex, ip, "192.0.2.55")
	}

	vlanID, mac, err := parseQBridgeFDBEntryOID(oidDot1qTpFdbPort, oidDot1qTpFdbPort+".20.222.173.190.239.16.32")
	if err != nil {
		t.Fatalf("parseQBridgeFDBEntryOID returned error: %v", err)
	}
	if vlanID != 20 || mac != "de:ad:be:ef:10:20" {
		t.Fatalf("parseQBridgeFDBEntryOID = (%d, %q), want (20, %q)", vlanID, mac, "de:ad:be:ef:10:20")
	}
}

func mustTime(t *testing.T, value string) time.Time {
	t.Helper()

	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("time.Parse returned error: %v", err)
	}

	return parsed
}
