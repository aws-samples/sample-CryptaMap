package output

import "testing"

func TestSanitizeCell(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"hyperlink formula", "=HYPERLINK(\"http://evil\",\"click\")", "'=HYPERLINK(\"http://evil\",\"click\")"},
		{"plus", "+1+1", "'+1+1"},
		{"minus", "-2+3", "'-2+3"},
		{"at", "@SUM(A1)", "'@SUM(A1)"},
		{"tab", "\tfoo", "'\tfoo"},
		{"carriage return", "\rfoo", "'\rfoo"},
		{"benign resource id", "arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket"},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeCell(tc.in); got != tc.want {
				t.Errorf("sanitizeCell(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
