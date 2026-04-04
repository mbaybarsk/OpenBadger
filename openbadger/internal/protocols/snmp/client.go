package snmp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/mbaybarsk/openbadger/internal/credentials"
)

const (
	oidSysDescr             = ".1.3.6.1.2.1.1.1.0"
	oidSysObjectID          = ".1.3.6.1.2.1.1.2.0"
	oidSysUpTime            = ".1.3.6.1.2.1.1.3.0"
	oidSysName              = ".1.3.6.1.2.1.1.5.0"
	oidSNMPEngineID         = ".1.3.6.1.6.3.10.2.1.1.0"
	oidIfDescr              = ".1.3.6.1.2.1.2.2.1.2"
	oidIfSpeed              = ".1.3.6.1.2.1.2.2.1.5"
	oidIfPhysAddress        = ".1.3.6.1.2.1.2.2.1.6"
	oidIfAdminStatus        = ".1.3.6.1.2.1.2.2.1.7"
	oidIfOperStatus         = ".1.3.6.1.2.1.2.2.1.8"
	oidIfName               = ".1.3.6.1.2.1.31.1.1.1.1"
	oidIfAlias              = ".1.3.6.1.2.1.31.1.1.1.18"
	oidARPPhysAddress       = ".1.3.6.1.2.1.4.22.1.2"
	oidDot1dBasePortIfIndex = ".1.3.6.1.2.1.17.1.4.1.2"
	oidDot1dTpFdbPort       = ".1.3.6.1.2.1.17.4.3.1.2"
	oidDot1qTpFdbPort       = ".1.3.6.1.2.1.17.7.1.2.2.1.2"
)

var ErrNoResponse = errors.New("snmp no response")

type Request struct {
	Target     string
	Port       int
	Timeout    time.Duration
	Retries    int
	Credential credentials.SNMPProfile
}

type Collector interface {
	Collect(ctx context.Context, request Request) (Result, error)
}

type Dialer interface {
	Dial(ctx context.Context, request Request) (Client, error)
}

type Client interface {
	Get(oids []string) (*gosnmp.SnmpPacket, error)
	WalkAll(rootOID string) ([]gosnmp.SnmpPDU, error)
	Close() error
}

type gosnmpCollector struct {
	dialer Dialer
}

type gosnmpDialer struct{}

type gosnmpClient struct {
	client *gosnmp.GoSNMP
}

func NewCollector(dialer Dialer) Collector {
	if dialer == nil {
		dialer = gosnmpDialer{}
	}

	return gosnmpCollector{dialer: dialer}
}

func (c gosnmpCollector) Collect(ctx context.Context, request Request) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	if strings.TrimSpace(request.Target) == "" {
		return Result{}, fmt.Errorf("snmp target is required")
	}

	if request.Timeout <= 0 {
		request.Timeout = 2 * time.Second
	}

	if request.Retries < 0 {
		return Result{}, fmt.Errorf("snmp retries are invalid")
	}

	if err := credentials.ValidateSNMPProfile(&request.Credential); err != nil {
		return Result{}, err
	}

	request.Port = credentials.DefaultSNMPPort(firstPositive(request.Port, request.Credential.Port))

	client, err := c.dialer.Dial(ctx, request)
	if err != nil {
		return Result{}, err
	}
	defer client.Close()

	system, err := collectSystem(client)
	if err != nil {
		return Result{}, err
	}

	return Result{
		System:     system,
		Interfaces: collectInterfaces(client),
		ARPEntries: collectARPEntries(client),
		FDBEntries: collectFDBEntries(client),
	}, nil
}

func (d gosnmpDialer) Dial(ctx context.Context, request Request) (Client, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	params := &gosnmp.GoSNMP{
		Target:             strings.TrimSpace(request.Target),
		Port:               uint16(credentials.DefaultSNMPPort(request.Port)),
		Timeout:            request.Timeout,
		Retries:            request.Retries,
		ExponentialTimeout: false,
	}

	version := credentials.NormalizeSNMPVersion(request.Credential.Version)
	switch version {
	case credentials.SNMPVersion2c:
		params.Version = gosnmp.Version2c
		params.Community = request.Credential.Community
	case credentials.SNMPVersion3:
		params.Version = gosnmp.Version3
		params.SecurityModel = gosnmp.UserSecurityModel
		params.ContextName = request.Credential.ContextName

		security := &gosnmp.UsmSecurityParameters{UserName: request.Credential.Username}
		authProtocol := credentials.NormalizeSNMPAuthProtocol(request.Credential.AuthProtocol)
		privacyProtocol := credentials.NormalizeSNMPPrivacyProtocol(request.Credential.PrivacyProtocol)

		switch {
		case authProtocol == "" && privacyProtocol == "":
			params.MsgFlags = gosnmp.NoAuthNoPriv
		case authProtocol != "" && privacyProtocol == "":
			params.MsgFlags = gosnmp.AuthNoPriv
		case authProtocol != "" && privacyProtocol != "":
			params.MsgFlags = gosnmp.AuthPriv
		}

		security.AuthenticationProtocol = gosnmp.NoAuth
		switch authProtocol {
		case "md5":
			security.AuthenticationProtocol = gosnmp.MD5
		case "sha":
			security.AuthenticationProtocol = gosnmp.SHA
		case "sha224":
			security.AuthenticationProtocol = gosnmp.SHA224
		case "sha256":
			security.AuthenticationProtocol = gosnmp.SHA256
		case "sha384":
			security.AuthenticationProtocol = gosnmp.SHA384
		case "sha512":
			security.AuthenticationProtocol = gosnmp.SHA512
		}
		security.AuthenticationPassphrase = request.Credential.AuthPassword

		security.PrivacyProtocol = gosnmp.NoPriv
		switch privacyProtocol {
		case "des":
			security.PrivacyProtocol = gosnmp.DES
		case "aes":
			security.PrivacyProtocol = gosnmp.AES
		case "aes192":
			security.PrivacyProtocol = gosnmp.AES192
		case "aes256":
			security.PrivacyProtocol = gosnmp.AES256
		}
		security.PrivacyPassphrase = request.Credential.PrivacyPassword
		params.SecurityParameters = security
	default:
		return nil, fmt.Errorf("snmp version %q is invalid", request.Credential.Version)
	}

	if err := params.Connect(); err != nil {
		if isNoResponseError(err) {
			return nil, ErrNoResponse
		}
		return nil, fmt.Errorf("connect snmp target %q: %w", request.Target, err)
	}

	return &gosnmpClient{client: params}, nil
}

func (c *gosnmpClient) Get(oids []string) (*gosnmp.SnmpPacket, error) {
	return c.client.Get(oids)
}

func (c *gosnmpClient) WalkAll(rootOID string) ([]gosnmp.SnmpPDU, error) {
	return c.client.WalkAll(rootOID)
}

func (c *gosnmpClient) Close() error {
	if c == nil || c.client == nil || c.client.Conn == nil {
		return nil
	}

	return c.client.Conn.Close()
}

func collectSystem(client Client) (SystemData, error) {
	var system SystemData

	if value, err := getString(client, oidSysName); err != nil {
		return SystemData{}, err
	} else {
		system.SysName = value
	}

	if value, err := getString(client, oidSysDescr); err != nil {
		return SystemData{}, err
	} else {
		system.SysDescr = value
	}

	if value, err := getString(client, oidSysObjectID); err != nil {
		return SystemData{}, err
	} else {
		system.SysObjectID = value
	}

	if value, err := getUint64(client, oidSysUpTime); err != nil {
		return SystemData{}, err
	} else {
		system.UptimeTicks = value
	}

	if value, err := getString(client, oidSNMPEngineID); err == nil {
		system.EngineID = value
	}

	return system, nil
}

func collectInterfaces(client Client) []InterfaceData {
	interfaces := make(map[int]*InterfaceData)
	apply := func(baseOID string, handler func(*InterfaceData, gosnmp.SnmpPDU)) {
		for _, pdu := range safeWalk(client, baseOID) {
			index, err := parseInterfaceIndex(baseOID, pdu.Name)
			if err != nil || index <= 0 {
				continue
			}

			iface := interfaces[index]
			if iface == nil {
				iface = &InterfaceData{Index: index}
				interfaces[index] = iface
			}

			handler(iface, pdu)
		}
	}

	apply(oidIfName, func(iface *InterfaceData, pdu gosnmp.SnmpPDU) { iface.Name = pduString(pdu) })
	apply(oidIfAlias, func(iface *InterfaceData, pdu gosnmp.SnmpPDU) { iface.Alias = pduString(pdu) })
	apply(oidIfDescr, func(iface *InterfaceData, pdu gosnmp.SnmpPDU) { iface.Description = pduString(pdu) })
	apply(oidIfAdminStatus, func(iface *InterfaceData, pdu gosnmp.SnmpPDU) { iface.AdminStatus = interfaceStatus(pduUint64(pdu)) })
	apply(oidIfOperStatus, func(iface *InterfaceData, pdu gosnmp.SnmpPDU) { iface.OperStatus = interfaceStatus(pduUint64(pdu)) })
	apply(oidIfSpeed, func(iface *InterfaceData, pdu gosnmp.SnmpPDU) { iface.SpeedBPS = pduUint64(pdu) })
	apply(oidIfPhysAddress, func(iface *InterfaceData, pdu gosnmp.SnmpPDU) { iface.MACAddress = pduMAC(pdu) })

	result := make([]InterfaceData, 0, len(interfaces))
	for _, iface := range interfaces {
		result = append(result, *iface)
	}

	return result
}

func collectARPEntries(client Client) []ARPEntry {
	entries := make([]ARPEntry, 0)
	for _, pdu := range safeWalk(client, oidARPPhysAddress) {
		ifIndex, ip, err := parseARPEntryOID(oidARPPhysAddress, pdu.Name)
		if err != nil {
			continue
		}

		mac := pduMAC(pdu)
		if ip == "" || mac == "" {
			continue
		}

		entries = append(entries, ARPEntry{InterfaceIndex: ifIndex, ObservedIP: ip, ObservedMAC: mac})
	}

	return entries
}

func collectFDBEntries(client Client) []FDBEntry {
	bridgePortIfIndex := make(map[int]int)
	for _, pdu := range safeWalk(client, oidDot1dBasePortIfIndex) {
		bridgePort, err := parseInterfaceIndex(oidDot1dBasePortIfIndex, pdu.Name)
		if err != nil || bridgePort <= 0 {
			continue
		}
		bridgePortIfIndex[bridgePort] = int(pduUint64(pdu))
	}

	entries := collectQBridgeFDBEntries(client, bridgePortIfIndex)
	if len(entries) > 0 {
		return entries
	}

	return collectBridgeFDBEntries(client, bridgePortIfIndex)
}

func collectQBridgeFDBEntries(client Client, bridgePortIfIndex map[int]int) []FDBEntry {
	entries := make([]FDBEntry, 0)
	for _, pdu := range safeWalk(client, oidDot1qTpFdbPort) {
		vlanID, mac, err := parseQBridgeFDBEntryOID(oidDot1qTpFdbPort, pdu.Name)
		if err != nil || mac == "" {
			continue
		}

		bridgePort := int(pduUint64(pdu))
		entries = append(entries, FDBEntry{
			BridgePort:     bridgePort,
			InterfaceIndex: bridgePortIfIndex[bridgePort],
			ObservedMAC:    mac,
			VLANID:         vlanID,
		})
	}

	return entries
}

func collectBridgeFDBEntries(client Client, bridgePortIfIndex map[int]int) []FDBEntry {
	entries := make([]FDBEntry, 0)
	for _, pdu := range safeWalk(client, oidDot1dTpFdbPort) {
		mac, err := parseFDBEntryOID(oidDot1dTpFdbPort, pdu.Name)
		if err != nil || mac == "" {
			continue
		}

		bridgePort := int(pduUint64(pdu))
		entries = append(entries, FDBEntry{
			BridgePort:     bridgePort,
			InterfaceIndex: bridgePortIfIndex[bridgePort],
			ObservedMAC:    mac,
		})
	}

	return entries
}

func safeWalk(client Client, rootOID string) []gosnmp.SnmpPDU {
	values, err := client.WalkAll(rootOID)
	if err != nil {
		return nil
	}

	return values
}

func getString(client Client, oid string) (string, error) {
	pdu, ok, err := getScalar(client, oid)
	if err != nil || !ok {
		return "", err
	}

	return pduString(pdu), nil
}

func getUint64(client Client, oid string) (uint64, error) {
	pdu, ok, err := getScalar(client, oid)
	if err != nil || !ok {
		return 0, err
	}

	return pduUint64(pdu), nil
}

func getScalar(client Client, oid string) (gosnmp.SnmpPDU, bool, error) {
	packet, err := client.Get([]string{oid})
	if err != nil {
		if isNoResponseError(err) {
			return gosnmp.SnmpPDU{}, false, ErrNoResponse
		}
		return gosnmp.SnmpPDU{}, false, err
	}

	if packet == nil || len(packet.Variables) == 0 {
		return gosnmp.SnmpPDU{}, false, nil
	}

	pdu := packet.Variables[0]
	switch pdu.Type {
	case gosnmp.NoSuchInstance, gosnmp.NoSuchObject, gosnmp.EndOfMibView:
		return gosnmp.SnmpPDU{}, false, nil
	default:
		return pdu, true, nil
	}
}

func pduString(pdu gosnmp.SnmpPDU) string {
	switch value := pdu.Value.(type) {
	case string:
		return strings.TrimSpace(value)
	case []byte:
		return strings.TrimSpace(string(value))
	default:
		return strings.TrimSpace(gosnmp.ToBigInt(value).String())
	}
}

func pduUint64(pdu gosnmp.SnmpPDU) uint64 {
	switch value := pdu.Value.(type) {
	case uint:
		return uint64(value)
	case uint8:
		return uint64(value)
	case uint16:
		return uint64(value)
	case uint32:
		return uint64(value)
	case uint64:
		return value
	case int:
		if value < 0 {
			return 0
		}
		return uint64(value)
	case int32:
		if value < 0 {
			return 0
		}
		return uint64(value)
	case int64:
		if value < 0 {
			return 0
		}
		return uint64(value)
	default:
		big := gosnmp.ToBigInt(value)
		if big == nil || big.Sign() < 0 {
			return 0
		}
		return big.Uint64()
	}
}

func pduMAC(pdu gosnmp.SnmpPDU) string {
	switch value := pdu.Value.(type) {
	case []byte:
		if len(value) == 0 {
			return ""
		}
		return normalizeMAC(fmt.Sprintf("% x", value))
	case string:
		return normalizeMAC(value)
	default:
		return normalizeMAC(pduString(pdu))
	}
}

func interfaceStatus(value uint64) string {
	switch value {
	case 1:
		return "up"
	case 2:
		return "down"
	default:
		return "unknown"
	}
}

func isNoResponseError(err error) bool {
	if err == nil {
		return false
	}

	message := strings.ToLower(err.Error())
	return strings.Contains(message, "request timeout") || strings.Contains(message, "i/o timeout") || strings.Contains(message, "deadline exceeded")
}

func firstPositive(values ...int) int {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}

	return 0
}
