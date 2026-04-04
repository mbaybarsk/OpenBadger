package ssh

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/mbaybarsk/openbadger/internal/credentials"
	cryptossh "golang.org/x/crypto/ssh"
)

var ErrNoResponse = errors.New("ssh no response")

var ErrAuthentication = errors.New("ssh authentication failed")

const defaultCollectTimeout = 5 * time.Second

const inventoryCommand = `sh -c '
printf "__OPENBADGER_HOSTNAME__\n"
hostname 2>/dev/null || true
printf "__OPENBADGER_FQDN__\n"
hostname -f 2>/dev/null || true
printf "__OPENBADGER_OS_RELEASE__\n"
(cat /etc/os-release 2>/dev/null || cat /usr/lib/os-release 2>/dev/null || true)
printf "__OPENBADGER_KERNEL_VERSION__\n"
uname -r 2>/dev/null || true
printf "__OPENBADGER_ARCHITECTURE__\n"
uname -m 2>/dev/null || true
printf "__OPENBADGER_MACHINE_ID__\n"
(cat /etc/machine-id 2>/dev/null || cat /var/lib/dbus/machine-id 2>/dev/null || true)
'`

const (
	sectionHostname      = "__OPENBADGER_HOSTNAME__"
	sectionFQDN          = "__OPENBADGER_FQDN__"
	sectionOSRelease     = "__OPENBADGER_OS_RELEASE__"
	sectionKernelVersion = "__OPENBADGER_KERNEL_VERSION__"
	sectionArchitecture  = "__OPENBADGER_ARCHITECTURE__"
	sectionMachineID     = "__OPENBADGER_MACHINE_ID__"
)

type Collector interface {
	Collect(ctx context.Context, request Request) (Result, error)
}

type Request struct {
	Target     string
	Port       int
	Timeout    time.Duration
	Credential credentials.SSHProfile
}

type OSRelease struct {
	Name       string
	PrettyName string
	ID         string
	IDLike     string
	Version    string
	VersionID  string
}

type Result struct {
	Hostname           string
	FQDN               string
	OSRelease          OSRelease
	KernelVersion      string
	Architecture       string
	HostKeyFingerprint string
	MachineID          string
}

type collector struct{}

func NewCollector() Collector {
	return collector{}
}

func (collector) Collect(ctx context.Context, request Request) (Result, error) {
	target := strings.TrimSpace(request.Target)
	if target == "" {
		return Result{}, fmt.Errorf("ssh target is required")
	}

	if err := credentials.ValidateSSHProfile(&request.Credential); err != nil {
		return Result{}, err
	}

	timeout := request.Timeout
	if timeout <= 0 {
		timeout = defaultCollectTimeout
	}

	port := request.Port
	if port <= 0 {
		port = credentials.DefaultSSHPort(request.Credential.Port)
	}

	authMethod, err := buildAuthMethod(request.Credential)
	if err != nil {
		return Result{}, err
	}

	address := net.JoinHostPort(target, strconv.Itoa(port))
	var hostKeyFingerprint string
	config := &cryptossh.ClientConfig{
		User: strings.TrimSpace(request.Credential.Username),
		Auth: []cryptossh.AuthMethod{authMethod},
		HostKeyCallback: func(_ string, _ net.Addr, key cryptossh.PublicKey) error {
			hostKeyFingerprint = cryptossh.FingerprintSHA256(key)
			return nil
		},
		Timeout: timeout,
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return Result{}, classifyError(err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return Result{}, fmt.Errorf("set ssh connection deadline: %w", err)
	}

	clientConn, chans, reqs, err := cryptossh.NewClientConn(conn, address, config)
	if err != nil {
		return Result{}, classifyError(err)
	}

	client := cryptossh.NewClient(clientConn, chans, reqs)
	defer client.Close()

	output, err := runInventoryCommand(ctx, client)
	if err != nil {
		return Result{}, classifyError(err)
	}

	sections := parseInventoryOutput(output)
	result := Result{
		Hostname:           strings.TrimSpace(sections[sectionHostname]),
		FQDN:               strings.TrimSpace(sections[sectionFQDN]),
		OSRelease:          ParseOSRelease(sections[sectionOSRelease]),
		KernelVersion:      strings.TrimSpace(sections[sectionKernelVersion]),
		Architecture:       strings.TrimSpace(sections[sectionArchitecture]),
		HostKeyFingerprint: strings.TrimSpace(hostKeyFingerprint),
		MachineID:          strings.TrimSpace(sections[sectionMachineID]),
	}

	if result.Hostname == "" && result.FQDN != "" {
		result.Hostname = hostnameFromFQDN(result.FQDN)
	}

	return result, nil
}

func buildAuthMethod(profile credentials.SSHProfile) (cryptossh.AuthMethod, error) {
	if strings.TrimSpace(profile.Password) != "" {
		return cryptossh.Password(profile.Password), nil
	}

	signer, err := credentials.ParseSSHPrivateKey(profile.PrivateKey, profile.Passphrase)
	if err != nil {
		return nil, err
	}

	return cryptossh.PublicKeys(signer), nil
}

func runInventoryCommand(ctx context.Context, client *cryptossh.Client) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("create ssh session: %w", err)
	}
	defer session.Close()

	type commandResult struct {
		output []byte
		err    error
	}

	done := make(chan commandResult, 1)
	go func() {
		output, err := session.CombinedOutput(inventoryCommand)
		done <- commandResult{output: output, err: err}
	}()

	select {
	case <-ctx.Done():
		_ = client.Close()
		result := <-done
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return strings.TrimSpace(string(result.output)), result.err
	case result := <-done:
		if result.err != nil {
			return strings.TrimSpace(string(result.output)), fmt.Errorf("run ssh inventory command: %w", result.err)
		}

		return strings.TrimSpace(string(result.output)), nil
	}
}

func parseInventoryOutput(output string) map[string]string {
	sections := map[string][]string{}
	current := ""
	scanner := bufio.NewScanner(strings.NewReader(strings.ReplaceAll(output, "\r\n", "\n")))
	for scanner.Scan() {
		line := scanner.Text()
		switch line {
		case sectionHostname, sectionFQDN, sectionOSRelease, sectionKernelVersion, sectionArchitecture, sectionMachineID:
			current = line
		default:
			if current != "" {
				sections[current] = append(sections[current], line)
			}
		}
	}

	flattened := make(map[string]string, len(sections))
	for section, lines := range sections {
		if section == sectionOSRelease {
			flattened[section] = strings.TrimSpace(strings.Join(lines, "\n"))
			continue
		}

		flattened[section] = firstNonEmpty(lines)
	}

	return flattened
}

func ParseOSRelease(raw string) OSRelease {
	var release OSRelease
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		key = strings.TrimSpace(key)
		value = parseOSReleaseValue(strings.TrimSpace(value))
		switch key {
		case "NAME":
			release.Name = value
		case "PRETTY_NAME":
			release.PrettyName = value
		case "ID":
			release.ID = value
		case "ID_LIKE":
			release.IDLike = value
		case "VERSION":
			release.Version = value
		case "VERSION_ID":
			release.VersionID = value
		}
	}

	return release
}

func parseOSReleaseValue(value string) string {
	if len(value) >= 2 && strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) {
		if unquoted, err := strconv.Unquote(value); err == nil {
			return unquoted
		}
	}

	if len(value) >= 2 && strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'") {
		return value[1 : len(value)-1]
	}

	return value
}

func classifyError(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return fmt.Errorf("%w: %v", ErrNoResponse, err)
	}

	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "unable to authenticate"), strings.Contains(lower, "no supported methods remain"), strings.Contains(lower, "permission denied"):
		return fmt.Errorf("%w: %v", ErrAuthentication, err)
	case strings.Contains(lower, "connection refused"), strings.Contains(lower, "connection reset"), strings.Contains(lower, "connection closed"), strings.Contains(lower, "connection timed out"), strings.Contains(lower, "network is unreachable"), strings.Contains(lower, "no route to host"), strings.Contains(lower, "i/o timeout"), strings.Contains(lower, "eof"):
		return fmt.Errorf("%w: %v", ErrNoResponse, err)
	default:
		return err
	}
}

func firstNonEmpty(lines []string) string {
	for _, line := range lines {
		if value := strings.TrimSpace(line); value != "" {
			return value
		}
	}

	return ""
}

func hostnameFromFQDN(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	if head, _, ok := strings.Cut(value, "."); ok {
		return head
	}

	return value
}
