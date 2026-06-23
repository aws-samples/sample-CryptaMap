package datarest

import "testing"

// TestIsSystemKeyspace verifies that the AWS-managed system keyspaces are
// skipped and that customer keyspaces — including names that merely start with
// "system" — are NOT over-matched (the set is exact-match, not a prefix match).
func TestIsSystemKeyspace(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		// AWS-managed system keyspaces -> skipped.
		{"system", true},
		{"system_schema", true},
		{"system_schema_mcs", true},
		{"system_multiregion_info", true},
		{"system_auth", true},
		{"system_distributed", true},
		{"system_traces", true},
		{"system_views", true},
		{"system_virtual_schema", true},

		// Customer keyspaces -> kept.
		{"myapp", false},
		{"prod_orders", false},
		{"", false},

		// Names that merely start with "system" must NOT be over-matched.
		{"system_app", false},
		{"systemstore", false},
		{"system_", false},
		{"System", false}, // case-sensitive: real system keyspaces are lowercase
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isSystemKeyspace(c.name); got != c.want {
				t.Errorf("isSystemKeyspace(%q) = %v, want %v", c.name, got, c.want)
			}
		})
	}
}
