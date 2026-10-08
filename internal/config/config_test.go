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
