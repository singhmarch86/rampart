package ipfilter

import (
	"net"
	"testing"
)

func TestAllowedDefaultAllowAll(t *testing.T) {
	f, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	allowed, _ := f.Allowed(net.ParseIP("198.51.100.7"))
	if !allowed {
		t.Fatal("expected allow-all when no lists configured")
	}
}

func TestDenyListBlocksMatchingIP(t *testing.T) {
	f, err := New(nil, []string{"203.0.113.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	allowed, reason := f.Allowed(net.ParseIP("203.0.113.55"))
	if allowed {
		t.Fatal("expected deny list to block matching IP")
	}
	if reason == "" {
		t.Fatal("expected a reason for the block")
	}

	allowed, _ = f.Allowed(net.ParseIP("198.51.100.7"))
	if !allowed {
		t.Fatal("expected non-matching IP to remain allowed")
	}
}

func TestAllowListRestrictsToListedIPs(t *testing.T) {
	f, err := New([]string{"10.0.0.0/8"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	allowed, _ := f.Allowed(net.ParseIP("10.1.2.3"))
	if !allowed {
		t.Fatal("expected IP inside allow list to pass")
	}
	allowed, _ = f.Allowed(net.ParseIP("198.51.100.7"))
	if allowed {
		t.Fatal("expected IP outside allow list to be blocked")
	}
}

func TestDenyTakesPrecedenceOverAllow(t *testing.T) {
	f, err := New([]string{"10.0.0.0/8"}, []string{"10.1.2.3/32"})
	if err != nil {
		t.Fatal(err)
	}
	allowed, _ := f.Allowed(net.ParseIP("10.1.2.3"))
	if allowed {
		t.Fatal("expected explicit deny to override a broader allow")
	}
}

func TestBareIPTreatedAsSingleHost(t *testing.T) {
	f, err := New(nil, []string{"203.0.113.5"})
	if err != nil {
		t.Fatal(err)
	}
	allowed, _ := f.Allowed(net.ParseIP("203.0.113.5"))
	if allowed {
		t.Fatal("expected bare IP in deny list to block exactly that IP")
	}
	allowed, _ = f.Allowed(net.ParseIP("203.0.113.6"))
	if !allowed {
		t.Fatal("expected bare IP deny to not affect neighboring IPs")
	}
}

func TestInvalidCIDRReturnsError(t *testing.T) {
	if _, err := New(nil, []string{"not-an-ip"}); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}
