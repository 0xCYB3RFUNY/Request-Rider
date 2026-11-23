package main

import (
	"strings"
	"testing"
)

func TestUserAgentsAreModernAndNeverLeakRequestRider(t *testing.T) {
	seenGeneral := make(map[string]bool)
	seenDesktop := make(map[string]bool)
	seenMobile := make(map[string]bool)

	for i := 0; i < 100; i++ {
		ua := RandomUserAgent()
		desktopUA := RandomDesktopUserAgent()
		mobileUA := RandomMobileUserAgent()

		for _, candidate := range []string{ua, desktopUA, mobileUA} {
			if strings.Contains(candidate, "RequestRider") || strings.Contains(candidate, "Request-Rider") {
				t.Fatalf("leaked RequestRider in User-Agent: %s", candidate)
			}
			if !strings.HasPrefix(candidate, "Mozilla/5.0") {
				t.Fatalf("unexpected User-Agent format: %s", candidate)
			}
		}

		if !strings.Contains(desktopUA, "Windows") && !strings.Contains(desktopUA, "Macintosh") && !strings.Contains(desktopUA, "X11") {
			t.Fatalf("desktop UA should contain desktop OS: %s", desktopUA)
		}

		if !strings.Contains(mobileUA, "iPhone") && !strings.Contains(mobileUA, "iPad") && !strings.Contains(mobileUA, "Android") {
			t.Fatalf("mobile UA should contain mobile OS: %s", mobileUA)
		}

		seenGeneral[ua] = true
		seenDesktop[desktopUA] = true
		seenMobile[mobileUA] = true
	}

	if len(seenGeneral) < 5 {
		t.Fatalf("expected diverse User-Agents, got %d distinct", len(seenGeneral))
	}
	if len(seenDesktop) < 5 {
		t.Fatalf("expected diverse desktop User-Agents, got %d distinct", len(seenDesktop))
	}
	if len(seenMobile) < 3 {
		t.Fatalf("expected diverse mobile User-Agents, got %d distinct", len(seenMobile))
	}
}
