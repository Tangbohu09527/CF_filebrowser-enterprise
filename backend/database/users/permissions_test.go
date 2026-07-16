package users

import (
	"reflect"
	"testing"
)

func TestCurrentPermissionsVersion(t *testing.T) {
	if CurrentPermissionsVersion != 4 {
		t.Fatalf("CurrentPermissionsVersion: got %d want 4", CurrentPermissionsVersion)
	}
}

func TestNormalizeLegacyPermissions(t *testing.T) {
	tests := []struct {
		name     string
		download bool
	}{
		{name: "download allowed", download: true},
		{name: "download denied", download: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			legacy := Permissions{
				Api:      true,
				Admin:    false,
				Modify:   true,
				Share:    false,
				Realtime: true,
				Delete:   false,
				Create:   true,
				Browse:   false,
				Preview:  false,
				Download: tc.download,
			}
			want := legacy
			want.Browse = true
			want.Preview = true

			got := NormalizeLegacyPermissions(legacy)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("NormalizeLegacyPermissions() = %+v, want %+v", got, want)
			}

			gotAgain := NormalizeLegacyPermissions(got)
			if !reflect.DeepEqual(gotAgain, got) {
				t.Fatalf("NormalizeLegacyPermissions() is not idempotent: first %+v, second %+v", got, gotAgain)
			}
		})
	}
}

func TestIntersectPermissions(t *testing.T) {
	all := Permissions{
		Api:      true,
		Admin:    true,
		Modify:   true,
		Share:    true,
		Realtime: true,
		Delete:   true,
		Create:   true,
		Browse:   true,
		Preview:  true,
		Download: true,
	}
	subset := Permissions{
		Api:      true,
		Admin:    false,
		Modify:   true,
		Share:    false,
		Realtime: true,
		Delete:   false,
		Create:   true,
		Browse:   false,
		Preview:  true,
		Download: false,
	}
	overlapLeft := Permissions{
		Api:      true,
		Browse:   true,
		Download: true,
	}
	overlapRight := Permissions{
		Api:      true,
		Preview:  true,
		Download: true,
	}
	overlapWant := Permissions{
		Api:      true,
		Download: true,
	}

	tests := []struct {
		name  string
		left  Permissions
		right Permissions
		want  Permissions
	}{
		{name: "token caps user", left: all, right: subset, want: subset},
		{name: "user caps token", left: subset, right: all, want: subset},
		{name: "only common fields survive", left: overlapLeft, right: overlapRight, want: overlapWant},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IntersectPermissions(tc.left, tc.right)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("IntersectPermissions() = %+v, want %+v", got, tc.want)
			}
		})
	}
}
