package ssh

import "testing"

func TestParseOSRelease(t *testing.T) {
	t.Parallel()

	release := ParseOSRelease(`
NAME="Ubuntu"
VERSION="22.04.4 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 22.04.4 LTS"
VERSION_ID="22.04"
`)

	if release.Name != "Ubuntu" {
		t.Fatalf("release.Name = %q, want %q", release.Name, "Ubuntu")
	}

	if release.Version != "22.04.4 LTS (Jammy Jellyfish)" {
		t.Fatalf("release.Version = %q, want full version", release.Version)
	}

	if release.ID != "ubuntu" || release.IDLike != "debian" || release.PrettyName != "Ubuntu 22.04.4 LTS" || release.VersionID != "22.04" {
		t.Fatalf("release = %#v, want parsed os-release fields", release)
	}
}

func TestParseInventoryOutput(t *testing.T) {
	t.Parallel()

	output := `__OPENBADGER_HOSTNAME__
web-01
__OPENBADGER_FQDN__
web-01.example.local
__OPENBADGER_OS_RELEASE__
NAME="Ubuntu"
VERSION_ID="22.04"
PRETTY_NAME="Ubuntu 22.04 LTS"
__OPENBADGER_KERNEL_VERSION__
6.8.0-31-generic
__OPENBADGER_ARCHITECTURE__
x86_64
__OPENBADGER_MACHINE_ID__
0123456789abcdef0123456789abcdef
`

	sections := parseInventoryOutput(output)
	if sections[sectionHostname] != "web-01" {
		t.Fatalf("sections[%q] = %q, want %q", sectionHostname, sections[sectionHostname], "web-01")
	}

	if sections[sectionFQDN] != "web-01.example.local" {
		t.Fatalf("sections[%q] = %q, want %q", sectionFQDN, sections[sectionFQDN], "web-01.example.local")
	}

	if sections[sectionKernelVersion] != "6.8.0-31-generic" || sections[sectionArchitecture] != "x86_64" {
		t.Fatalf("sections = %#v, want parsed scalar inventory fields", sections)
	}

	release := ParseOSRelease(sections[sectionOSRelease])
	if release.Name != "Ubuntu" || release.VersionID != "22.04" || release.PrettyName != "Ubuntu 22.04 LTS" {
		t.Fatalf("release = %#v, want parsed os-release block", release)
	}
}
