package ratelimit

import (
	"net"
	"testing"
	"time"
)

func TestAllowBlocksAfterBurstExhausted(t *testing.T) {
	l := New(1, 2, 0, time.Minute)
	defer l.Close()
	ip := net.ParseIP("198.51.100.1")

	if !l.Allow(ip) {
		t.Fatal("expected first request within burst to be allowed")
	}
	if !l.Allow(ip) {
		t.Fatal("expected second request within burst to be allowed")
	}
	if l.Allow(ip) {
		t.Fatal("expected third immediate request to exceed burst and be blocked")
	}
}

func TestAllowIsPerIP(t *testing.T) {
	l := New(1, 1, 0, time.Minute)
	defer l.Close()
	ipA := net.ParseIP("198.51.100.1")
	ipB := net.ParseIP("198.51.100.2")

	if !l.Allow(ipA) {
		t.Fatal("expected ipA first request allowed")
	}
	if l.Allow(ipA) {
		t.Fatal("expected ipA second immediate request blocked")
	}
	if !l.Allow(ipB) {
		t.Fatal("expected ipB to have its own independent bucket")
	}
}

func TestConcurrencyCapEnforced(t *testing.T) {
	l := New(1000, 1000, 2, time.Minute)
	defer l.Close()
	ip := net.ParseIP("198.51.100.1")

	if !l.Begin(ip) {
		t.Fatal("expected first in-flight slot to be granted")
	}
	if !l.Begin(ip) {
		t.Fatal("expected second in-flight slot to be granted")
	}
	if l.Begin(ip) {
		t.Fatal("expected third in-flight slot to be denied at cap of 2")
	}

	l.End(ip)
	if !l.Begin(ip) {
		t.Fatal("expected a slot to free up after End")
	}
}

func TestConcurrencyCapDisabledWhenNonPositive(t *testing.T) {
	l := New(1000, 1000, 0, time.Minute)
	defer l.Close()
	ip := net.ParseIP("198.51.100.1")

	for i := 0; i < 100; i++ {
		if !l.Begin(ip) {
			t.Fatalf("expected Begin to always succeed when cap disabled, failed at i=%d", i)
		}
	}
}
