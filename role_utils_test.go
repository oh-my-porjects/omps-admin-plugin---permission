package main

import "testing"

func TestValidUUIDAcceptsShortIDAndUUID(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want bool
	}{
		{name: "short id", id: "AdminRole001", want: true},
		{name: "uuid", id: "00000000-0000-0000-0000-000000000001", want: true},
		{name: "invalid", id: "Root", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validUUID(tt.id); got != tt.want {
				t.Fatalf("validUUID(%q) = %v, want %v", tt.id, got, tt.want)
			}
		})
	}
}
