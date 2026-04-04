package winrm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	gowinrm "github.com/masterzen/winrm"
	"github.com/mbaybarsk/openbadger/internal/credentials"
)

var ErrNoResponse = errors.New("winrm no response")

var ErrAuthentication = errors.New("winrm authentication failed")

const defaultCollectTimeout = 5 * time.Second

const inventoryScript = `$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
$operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
$bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
$product = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction SilentlyContinue
$networkAddresses = @()
Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True" -ErrorAction SilentlyContinue | ForEach-Object {
  foreach ($ip in $_.IPAddress) {
    if ($ip) {
      $networkAddresses += $ip
    }
  }
}
$result = [ordered]@{
  hostname = if ($computerSystem -and $computerSystem.DNSHostName) { $computerSystem.DNSHostName } else { $env:COMPUTERNAME }
  domain = if ($computerSystem) { $computerSystem.Domain } else { $null }
  part_of_domain = if ($computerSystem) { [bool]$computerSystem.PartOfDomain } else { $null }
  os_name = if ($operatingSystem) { $operatingSystem.Caption } else { $null }
  os_version = if ($operatingSystem) { $operatingSystem.Version } else { $null }
  build_number = if ($operatingSystem) { $operatingSystem.BuildNumber } else { $null }
  manufacturer = if ($computerSystem) { $computerSystem.Manufacturer } else { $null }
  model = if ($computerSystem) { $computerSystem.Model } else { $null }
  serial_number = if ($bios) { $bios.SerialNumber } else { $null }
  system_uuid = if ($product) { $product.UUID } else { $null }
  network_addresses = @($networkAddresses | Where-Object { $_ } | Sort-Object -Unique)
}
$result | ConvertTo-Json -Compress -Depth 4`

type Collector interface {
	Collect(ctx context.Context, request Request) (Result, error)
}

type Request struct {
	Target     string
	Port       int
	Timeout    time.Duration
	Credential credentials.WinRMProfile
}

type Result struct {
	Hostname         string
	Domain           string
	PartOfDomain     bool
	OSName           string
	OSVersion        string
	BuildNumber      string
	Manufacturer     string
	Model            string
	SerialNumber     string
	SystemUUID       string
	NetworkAddresses []string
}

type inventoryPayload struct {
	Hostname         string   `json:"hostname"`
	Domain           string   `json:"domain"`
	PartOfDomain     bool     `json:"part_of_domain"`
	OSName           string   `json:"os_name"`
	OSVersion        string   `json:"os_version"`
	BuildNumber      string   `json:"build_number"`
	Manufacturer     string   `json:"manufacturer"`
	Model            string   `json:"model"`
	SerialNumber     string   `json:"serial_number"`
	SystemUUID       string   `json:"system_uuid"`
	NetworkAddresses []string `json:"network_addresses"`
}

type collector struct{}

func NewCollector() Collector {
	return collector{}
}

func (collector) Collect(ctx context.Context, request Request) (Result, error) {
	target := strings.TrimSpace(request.Target)
	if target == "" {
		return Result{}, fmt.Errorf("winrm target is required")
	}

	if err := credentials.ValidateWinRMProfile(&request.Credential); err != nil {
		return Result{}, err
	}

	timeout := request.Timeout
	if timeout <= 0 {
		timeout = defaultCollectTimeout
	}

	useHTTPS := credentials.WinRMUsesHTTPS(&request.Credential)
	port := request.Port
	if port <= 0 {
		port = credentials.DefaultWinRMPort(request.Credential.Port, useHTTPS)
	}

	endpoint := gowinrm.NewEndpoint(target, port, useHTTPS, request.Credential.InsecureTLS, nil, nil, nil, timeout)
	endpoint.TLSServerName = strings.TrimSpace(request.Credential.TLSServerName)

	params := gowinrm.NewParameters(operationTimeout(timeout), "en-US", 153600)
	client, err := gowinrm.NewClientWithParameters(endpoint, strings.TrimSpace(request.Credential.Username), request.Credential.Password, params)
	if err != nil {
		return Result{}, classifyError(err)
	}

	stdout, stderr, exitCode, err := client.RunPSWithContext(ctx, inventoryScript)
	if err != nil {
		if trimmed := strings.TrimSpace(stderr); trimmed != "" {
			return Result{}, classifyError(fmt.Errorf("%w: %s", err, trimmed))
		}

		return Result{}, classifyError(err)
	}

	if exitCode != 0 {
		runErr := fmt.Errorf("winrm inventory command exited with code %d", exitCode)
		if trimmed := strings.TrimSpace(stderr); trimmed != "" {
			runErr = fmt.Errorf("%w: %s", runErr, trimmed)
		}

		return Result{}, classifyError(runErr)
	}

	result, err := parseInventoryResult(stdout)
	if err != nil {
		return Result{}, err
	}

	return result, nil
}

func parseInventoryResult(raw string) (Result, error) {
	var payload inventoryPayload
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &payload); err != nil {
		return Result{}, fmt.Errorf("decode winrm inventory result: %w", err)
	}

	return Result{
		Hostname:         strings.TrimSpace(payload.Hostname),
		Domain:           strings.TrimSpace(payload.Domain),
		PartOfDomain:     payload.PartOfDomain,
		OSName:           strings.TrimSpace(payload.OSName),
		OSVersion:        strings.TrimSpace(payload.OSVersion),
		BuildNumber:      strings.TrimSpace(payload.BuildNumber),
		Manufacturer:     strings.TrimSpace(payload.Manufacturer),
		Model:            strings.TrimSpace(payload.Model),
		SerialNumber:     strings.TrimSpace(payload.SerialNumber),
		SystemUUID:       strings.TrimSpace(payload.SystemUUID),
		NetworkAddresses: append([]string(nil), payload.NetworkAddresses...),
	}, nil
}

func operationTimeout(timeout time.Duration) string {
	seconds := int(math.Ceil(timeout.Seconds()))
	if seconds <= 0 {
		seconds = 1
	}

	return fmt.Sprintf("PT%dS", seconds)
}

func classifyError(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}

	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "401"), strings.Contains(lower, "unauthorized"), strings.Contains(lower, "access is denied"), strings.Contains(lower, "credentials were rejected"):
		return fmt.Errorf("%w: %v", ErrAuthentication, err)
	case strings.Contains(lower, "connection refused"), strings.Contains(lower, "connection reset"), strings.Contains(lower, "connection timed out"), strings.Contains(lower, "network is unreachable"), strings.Contains(lower, "no route to host"), strings.Contains(lower, "i/o timeout"), strings.Contains(lower, "eof"):
		return fmt.Errorf("%w: %v", ErrNoResponse, err)
	default:
		return err
	}
}
