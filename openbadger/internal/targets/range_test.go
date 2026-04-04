package targets

import (
	"reflect"
	"testing"
)

func TestExpanderExpandCIDRWithExclusions(t *testing.T) {
	t.Parallel()

	expanded, err := (Expander{}).Expand([]Range{{
		CIDR:       "192.0.2.0/29",
		Exclusions: []string{"192.0.2.2", "192.0.2.4/31"},
	}})
	if err != nil {
		t.Fatalf("Expand returned error: %v", err)
	}

	got := make([]string, 0, len(expanded))
	for _, target := range expanded {
		got = append(got, target.IP)
	}

	want := []string{"192.0.2.1", "192.0.2.3", "192.0.2.6"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expanded IPs = %#v, want %#v", got, want)
	}
}

func TestExpanderExpandDeduplicatesAcrossRanges(t *testing.T) {
	t.Parallel()

	expanded, err := (Expander{}).Expand([]Range{
		{CIDR: "192.0.2.1/32"},
		{CIDR: "192.0.2.0/30"},
	})
	if err != nil {
		t.Fatalf("Expand returned error: %v", err)
	}

	got := make([]string, 0, len(expanded))
	for _, target := range expanded {
		got = append(got, target.IP)
	}

	want := []string{"192.0.2.1", "192.0.2.2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expanded IPs = %#v, want %#v", got, want)
	}
}

func TestExpanderExpandValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		ranges []Range
		want   string
	}{
		{name: "missing cidr", ranges: []Range{{}}, want: "targets[0]: cidr is required"},
		{name: "invalid exclusion", ranges: []Range{{CIDR: "192.0.2.0/30", Exclusions: []string{"bad-ip"}}}, want: "targets[0]: parse exclusion 0 \"bad-ip\":"},
		{name: "too large", ranges: []Range{{CIDR: "10.0.0.0/8"}}, want: "targets[0]: cidr \"10.0.0.0/8\" expands beyond limit 65536"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := (Expander{}).Expand(tt.ranges)
			if err == nil {
				t.Fatalf("Expand() error = nil, want %q", tt.want)
			}

			if tt.name == "invalid exclusion" {
				if got := err.Error(); len(got) < len(tt.want) || got[:len(tt.want)] != tt.want {
					t.Fatalf("Expand() error = %q, want prefix %q", err.Error(), tt.want)
				}
				return
			}

			if err.Error() != tt.want {
				t.Fatalf("Expand() error = %q, want %q", err.Error(), tt.want)
			}
		})
	}
}
