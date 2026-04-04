package jobs

import (
	"errors"
	"testing"
)

func TestValidateTransition(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		from    Status
		to      Status
		wantErr bool
	}{
		{name: "queued to running", from: StatusQueued, to: StatusRunning},
		{name: "running to success", from: StatusRunning, to: StatusSuccess},
		{name: "running to failed", from: StatusRunning, to: StatusFailed},
		{name: "queued to success", from: StatusQueued, to: StatusSuccess, wantErr: true},
		{name: "running to queued", from: StatusRunning, to: StatusQueued, wantErr: true},
		{name: "success to failed", from: StatusSuccess, to: StatusFailed, wantErr: true},
		{name: "failed to running", from: StatusFailed, to: StatusRunning, wantErr: true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateTransition(tt.from, tt.to)
			if tt.wantErr {
				if err == nil {
					t.Fatal("ValidateTransition returned nil error")
				}

				if !errors.Is(err, ErrInvalidTransition) {
					t.Fatalf("ValidateTransition error = %v, want ErrInvalidTransition", err)
				}

				return
			}

			if err != nil {
				t.Fatalf("ValidateTransition returned error: %v", err)
			}
		})
	}
}

func TestValidateTransitionRejectsInvalidStatuses(t *testing.T) {
	t.Parallel()

	if err := ValidateTransition(Status("invalid"), StatusRunning); err == nil {
		t.Fatal("ValidateTransition returned nil error for invalid source status")
	}

	if err := ValidateTransition(StatusQueued, Status("invalid")); err == nil {
		t.Fatal("ValidateTransition returned nil error for invalid target status")
	}
}
