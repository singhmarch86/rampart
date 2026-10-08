package config

import "testing"

func TestDefaultParanoiaLevelIsOne(t *testing.T) {
	if got := Default().WAF.ParanoiaLevel; got != 1 {
		t.Fatalf("default paranoia level should be 1 (CRS's own default), got %d", got)
	}
	if err := Default().Validate(); err != nil {
		t.Fatalf("default config should be valid: %v", err)
	}
}

func TestParanoiaLevelMustBeOneToFour(t *testing.T) {
	for _, level := range []int{1, 2, 3, 4} {
		c := Default()
		c.WAF.ParanoiaLevel = level
		if err := c.Validate(); err != nil {
			t.Errorf("level %d should be valid: %v", level, err)
		}
	}
	for _, level := range []int{0, -1, 5, 100} {
		c := Default()
		c.WAF.ParanoiaLevel = level
		if err := c.Validate(); err == nil {
			t.Errorf("level %d should be rejected", level)
		}
	}
}

func TestAllowedHostsValidation(t *testing.T) {
	c := Default()
	if len(c.AllowedHosts) != 0 {
		t.Fatalf("allowed_hosts must default to empty (check disabled), got %v", c.AllowedHosts)
	}
	c.AllowedHosts = []string{"example.com", "*.example.com", "api.example.com:8443"}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid allowed_hosts rejected: %v", err)
	}
	for _, bad := range []string{"https://example.com", "example.com/x", "", "a*b.com"} {
		c.AllowedHosts = []string{bad}
		if err := c.Validate(); err == nil {
			t.Errorf("allowed_hosts %q should be rejected", bad)
		}
	}
}
