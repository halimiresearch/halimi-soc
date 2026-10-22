package parser

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/halimi/halimisoc/internal/events/model"
)

func refTime() time.Time {
	return time.Date(2025, 8, 19, 12, 0, 0, 0, time.UTC)
}

func line(raw string) Line {
	return Line{
		Raw:        raw,
		Host:       "web-01",
		AgentID:    "agt_test",
		SourcePath: "auth.log",
		ObservedAt: refTime(),
	}
}

func TestSSHParserClassification(t *testing.T) {
	p := &SSHParser{}

	cases := []struct {
		name    string
		raw     string
		typ     model.EventType
		outcome model.Outcome
		actor   string
		srcIP   string
		port    int
	}{
		{
			name:    "failed password",
			raw:     `Aug 19 11:20:30 web-01 sshd[1823]: Failed password for root from 203.0.113.7 port 51022 ssh2`,
			typ:     model.TypeSSHLoginFailed,
			outcome: model.OutcomeFailure,
			actor:   "root",
			srcIP:   "203.0.113.7",
			port:    51022,
		},
		{
			name:    "failed password for invalid user",
			raw:     `Aug 19 11:20:31 web-01 sshd[1823]: Failed password for invalid user admin from 203.0.113.7 port 51023 ssh2`,
			typ:     model.TypeSSHLoginFailed,
			outcome: model.OutcomeFailure,
			actor:   "admin",
			srcIP:   "203.0.113.7",
			port:    51023,
		},
		{
			name:    "accepted password",
			raw:     `Aug 19 11:21:01 web-01 sshd[1830]: Accepted password for alice from 198.51.100.4 port 40001 ssh2`,
			typ:     model.TypeSSHLoginSuccess,
			outcome: model.OutcomeSuccess,
			actor:   "alice",
			srcIP:   "198.51.100.4",
			port:    40001,
		},
		{
			name:    "accepted publickey logs fingerprint",
			raw:     `Aug 19 11:21:02 web-01 sshd[1831]: Accepted publickey for bob from 198.51.100.5 port 40002 ssh2: RSA SHA256:AbCdEf root@laptop`,
			typ:     model.TypeSSHLoginSuccess,
			outcome: model.OutcomeSuccess,
			actor:   "bob",
			srcIP:   "198.51.100.5",
			port:    40002,
		},
		{
			name:    "invalid user",
			raw:     `Aug 19 11:20:29 web-01 sshd[1821]: Invalid user oracle from 203.0.113.7 port 51010`,
			typ:     model.TypeSSHInvalidUser,
			outcome: model.OutcomeFailure,
			actor:   "oracle",
			srcIP:   "203.0.113.7",
			port:    51010,
		},
		{
			name:    "max attempts exceeded",
			raw:     `Aug 19 11:20:35 web-01 sshd[1824]: error: maximum authentication attempts exceeded for root from 203.0.113.7 port 51030 ssh2 [preauth]`,
			typ:     model.TypeSSHLoginFailed,
			outcome: model.OutcomeFailure,
			actor:   "root",
			srcIP:   "203.0.113.7",
			port:    51030,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !p.Match(tc.raw) {
				t.Fatal("Match() = false, want true")
			}
			res := p.Parse(line(tc.raw))
			if res.Status != StatusValid {
				t.Fatalf("status = %s (%s), want VALID", res.Status, res.Reason)
			}
			e := res.Event
			if e.Type != tc.typ {
				t.Errorf("type = %s, want %s", e.Type, tc.typ)
			}
			if e.Outcome != tc.outcome {
				t.Errorf("outcome = %s, want %s", e.Outcome, tc.outcome)
			}
			if e.Actor != tc.actor {
				t.Errorf("actor = %q, want %q", e.Actor, tc.actor)
			}
			if e.Network.SourceIP != tc.srcIP {
				t.Errorf("source_ip = %q, want %q", e.Network.SourceIP, tc.srcIP)
			}
			if e.Network.SourcePort != tc.port {
				t.Errorf("source_port = %d, want %d", e.Network.SourcePort, tc.port)
			}
			if e.Raw != tc.raw {
				t.Error("raw evidence was not retained verbatim")
			}
			if e.Source != model.SourceAuthLog {
				t.Errorf("source = %s, want auth.log", e.Source)
			}
		})
	}
}

func TestSSHParserTimestampIsParsedNotAssumed(t *testing.T) {
	p := &SSHParser{}
	raw := `Aug 19 11:20:30 web-01 sshd[1823]: Failed password for root from 203.0.113.7 port 51022 ssh2`
	res := p.Parse(line(raw))
	want := time.Date(2025, 8, 19, 11, 20, 30, 0, time.UTC)
	if !res.Event.Time.Equal(want) {
		t.Fatalf("time = %s, want %s", res.Event.Time, want)
	}
	if res.Event.Attributes["timestamp_source"] != "" {
		t.Error("parsed timestamp should not be marked as observed-time fallback")
	}
}

func TestSSHParserFallsBackToObservedTime(t *testing.T) {
	p := &SSHParser{}
	raw := `sshd[1823]: Failed password for root from 203.0.113.7 port 51022 ssh2`
	res := p.Parse(line(raw))
	if res.Status != StatusValid {
		t.Fatalf("status = %s, want VALID", res.Status)
	}
	if !res.Event.Time.Equal(refTime()) {
		t.Fatalf("time = %s, want observed %s", res.Event.Time, refTime())
	}
	if res.Event.Attributes["timestamp_source"] != "observed" {
		t.Error("fallback timestamp must be marked so analysts can distrust it")
	}
}

func TestSSHParserUnmodeledRecordIsNotMalformed(t *testing.T) {
	p := &SSHParser{}
	raw := `Aug 19 11:20:30 web-01 sshd[1823]: Server listening on 0.0.0.0 port 22.`
	res := p.Parse(line(raw))
	if res.Status != StatusNonSecurityRelevant {
		t.Fatalf("status = %s, want NON_SECURITY_RELEVANT", res.Status)
	}
	if res.Event != nil {
		t.Fatal("non-security-relevant record must not produce an event")
	}
}

func TestSSHParserNeverPanicsOnAdversarialInput(t *testing.T) {
	p := &SSHParser{}
	inputs := []string{
		"",
		"sshd",
		"sshd[",
		"sshd[]:",
		"sshd[1]:",
		`Aug 19 11:20:30 host sshd[1]: Failed password for  from  port  ssh2`,
		`Aug 19 11:20:30 host sshd[1]: Failed password for x from not-an-ip port not-a-port`,
		`Aug 19 11:20:30 host sshd[1]: Failed password for ` + strings.Repeat("A", 10000) + ` from 1.2.3.4 port 22`,
		`Aug 19 11:20:30 host sshd[1]: Accepted password for x from 999.999.999.999 port 99999`,
		"\x00\x01\x02 sshd[1]: Failed password",
	}
	for _, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on %q: %v", in, r)
				}
			}()
			res := p.Parse(line(in))
			if res.Status == StatusValid && res.Event == nil {
				t.Fatalf("VALID status with nil event for %q", in)
			}
		}()
	}
}

func TestSudoParserCommand(t *testing.T) {
	p := &SudoParser{}
	raw := `Aug 19 11:22:01 web-01 sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow`
	if !p.Match(raw) {
		t.Fatal("Match() = false, want true")
	}
	res := p.Parse(line(raw))
	if res.Status != StatusValid {
		t.Fatalf("status = %s (%s), want VALID", res.Status, res.Reason)
	}
	e := res.Event
	if e.Type != model.TypeSudoCommand {
		t.Errorf("type = %s, want %s", e.Type, model.TypeSudoCommand)
	}
	if e.Actor != "alice" || e.Target != "root" {
		t.Errorf("actor/target = %q/%q, want alice/root", e.Actor, e.Target)
	}
	if got := e.Attributes["command"]; got != "/usr/bin/cat /etc/shadow" {
		t.Errorf("command = %q", got)
	}
	if got := e.Attributes["runas"]; got != "root" {
		t.Errorf("runas = %q, want root", got)
	}
}

func TestSudoParserFlagsAuthorizedKeysPersistence(t *testing.T) {
	p := &SudoParser{}
	raw := `Aug 19 11:22:01 web-01 sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/sh -c echo key >> /root/.ssh/authorized_keys`
	res := p.Parse(line(raw))
	if res.Status != StatusValid {
		t.Fatalf("status = %s (%s), want VALID", res.Status, res.Reason)
	}
	if res.Event.Attributes["authorized_keys_modified"] != "true" {
		t.Error("expected persistence attribute to be set")
	}
	if res.Event.Severity != model.SeverityCritical {
		t.Errorf("severity = %s, want critical", res.Event.Severity)
	}
}

func TestSudoParserIncorrectPasswordAttempts(t *testing.T) {
	p := &SudoParser{}
	raw := `Aug 19 11:22:01 web-01 sudo: alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash`
	res := p.Parse(line(raw))
	if res.Status != StatusValid {
		t.Fatalf("status = %s, want VALID", res.Status)
	}
	if res.Event.Type != model.TypeSudoAuthFailed {
		t.Errorf("type = %s, want %s", res.Event.Type, model.TypeSudoAuthFailed)
	}
	if res.Event.Outcome != model.OutcomeFailure {
		t.Errorf("outcome = %s, want failure", res.Event.Outcome)
	}
	if res.Event.Attributes["attempts"] != "3" {
		t.Errorf("attempts = %q, want 3", res.Event.Attributes["attempts"])
	}
}

func TestSudoParserPamAuthFailure(t *testing.T) {
	p := &SudoParser{}
	raw := `Aug 19 11:22:01 web-01 sudo: pam_unix(sudo:auth): authentication failure; logname=alice uid=1000 euid=0 tty=/dev/pts/0 ruser= rhost= user=alice`
	res := p.Parse(line(raw))
	if res.Status != StatusValid {
		t.Fatalf("status = %s (%s), want VALID", res.Status, res.Reason)
	}
	if res.Event.Type != model.TypeSudoAuthFailed {
		t.Errorf("type = %s, want %s", res.Event.Type, model.TypeSudoAuthFailed)
	}
	if res.Event.Actor != "alice" {
		t.Errorf("actor = %q, want alice", res.Event.Actor)
	}
}

func TestSudoParserTrailingLognameDoesNotPanic(t *testing.T) {
	p := &SudoParser{}
	inputs := []string{
		`Aug 19 11:22:01 web-01 sudo: pam_unix(sudo:auth): authentication failure; logname=`,
		`Aug 19 11:22:01 web-01 sudo: pam_unix(sudo:auth): authentication failure; logname=   `,
	}
	for _, raw := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on %q: %v", raw, r)
				}
			}()
			res := p.Parse(line(raw))
			if res.Status != StatusValid || res.Event == nil {
				t.Fatalf("status = %s on %q, want a valid event", res.Status, raw)
			}
			if res.Event.Actor != "" {
				t.Errorf("actor = %q, want empty when logname has no value", res.Event.Actor)
			}
		}()
	}
}

func TestAuthorizedKeysParserRequiresVerb(t *testing.T) {
	p := &AuthorizedKeysParser{}

	if p.Match(`Aug 19 11:20:30 host kernel: reading /etc/ssh/authorized_keys.d`) {
		t.Error("a bare path mention must not match")
	}
	raw := `Aug 19 11:20:30 web-01 auditd: file=/root/.ssh/authorized_keys modified by user=alice`
	if !p.Match(raw) {
		t.Fatal("Match() = false, want true")
	}
	res := p.Parse(line(raw))
	if res.Status != StatusValid {
		t.Fatalf("status = %s, want VALID", res.Status)
	}
	if res.Event.Type != model.TypeAuthorizedKeys {
		t.Errorf("type = %s, want %s", res.Event.Type, model.TypeAuthorizedKeys)
	}
	if res.Event.Severity != model.SeverityCritical {
		t.Errorf("severity = %s, want critical", res.Event.Severity)
	}
}

func TestRegistrySelectsMostSpecificParserFirst(t *testing.T) {
	reg := Default()

	raw := `Aug 19 11:20:30 host sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2`
	if got := reg.Select(raw).Name(); got != "sshd" {
		t.Errorf("parser = %q, want sshd", got)
	}

	// A sudo line whose command mentions authorized_keys must stay a sudo
	// event: the privilege-escalation evidence is the sudo record itself.
	raw = `Aug 19 11:20:30 host sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cp x /root/.ssh/authorized_keys`
	if got := reg.Select(raw).Name(); got != "sudo" {
		t.Errorf("parser = %q, want sudo", got)
	}
}

func TestRegistryParseAddsParserAttribute(t *testing.T) {
	reg := Default()
	res := reg.Parse(line(`Aug 19 11:20:30 host sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2`))
	if res.Status != StatusValid {
		t.Fatalf("status = %s, want VALID", res.Status)
	}
	if res.Event.Attributes["parser"] != "sshd" {
		t.Errorf("parser attribute = %q, want sshd", res.Event.Attributes["parser"])
	}
}

func TestRegistryClassifiesUnknownAndEmpty(t *testing.T) {
	reg := Default()

	res := reg.Parse(line("some unrelated kernel message"))
	if res.Status != StatusUnsupported {
		t.Errorf("status = %s, want UNSUPPORTED", res.Status)
	}

	res = reg.Parse(line("   "))
	if res.Status != StatusNonSecurityRelevant {
		t.Errorf("status = %s, want NON_SECURITY_RELEVANT", res.Status)
	}
}

func TestParseTimeYearRollover(t *testing.T) {
	// A record written on 31 December must not be placed a year in the future
	// when it is read on 1 January.
	ref := time.Date(2025, 1, 1, 0, 30, 0, 0, time.UTC)
	got, ok := ParseTime("Dec 31 23:59:00", ref)
	if !ok {
		t.Fatal("ParseTime failed")
	}
	want := time.Date(2024, 12, 31, 23, 59, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("time = %s, want %s", got, want)
	}
}

func TestParseTimeRejectsGarbage(t *testing.T) {
	if _, ok := ParseTime("not-a-timestamp", refTime()); ok {
		t.Fatal("ParseTime accepted garbage")
	}
}

func TestAssemblerJoinsContinuationLines(t *testing.T) {
	a := NewAssembler(1024, 4096)
	chunk := "Aug 19 11:20:30 host sshd[1]: Failed password for root from 1.2.3.4 port 22\n continuation detail\nAug 19 11:20:31 host sshd[1]: Accepted password for a from 1.2.3.4 port 23\n"

	got := a.Feed(chunk)
	want := []string{
		"Aug 19 11:20:30 host sshd[1]: Failed password for root from 1.2.3.4 port 22\n continuation detail",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Feed() = %#v, want %#v", got, want)
	}

	// The final record is held until the stream is known to be idle.
	tail := a.Flush()
	wantTail := []string{"Aug 19 11:20:31 host sshd[1]: Accepted password for a from 1.2.3.4 port 23"}
	if !reflect.DeepEqual(tail, wantTail) {
		t.Fatalf("Flush() = %#v, want %#v", tail, wantTail)
	}
}

// TestAssemblerHoldsLastRecord pins the hold-last contract. Changing it to emit
// eagerly would silently break multi-line record assembly.
func TestAssemblerHoldsLastRecord(t *testing.T) {
	a := NewAssembler(1024, 4096)
	if got := a.Feed("only record\n"); len(got) != 0 {
		t.Fatalf("Feed() returned %d records, want 0 (record must be held)", len(got))
	}
	if got := a.Flush(); len(got) != 1 {
		t.Fatalf("Flush() returned %d records, want 1", len(got))
	}
}

func TestAssemblerHandlesPartialChunks(t *testing.T) {
	a := NewAssembler(1024, 4096)
	if got := a.Feed("Aug 19 11:20:3"); len(got) != 0 {
		t.Fatalf("incomplete chunk produced %d records", len(got))
	}
	if got := a.Feed("0 host sshd[1]: Failed password for root from 1.2.3.4 port 22\n"); len(got) != 0 {
		t.Fatalf("held record emitted early: %d records", len(got))
	}
	got := a.Flush()
	if len(got) != 1 {
		t.Fatalf("expected 1 record after flush, got %d", len(got))
	}
	if got[0] != "Aug 19 11:20:30 host sshd[1]: Failed password for root from 1.2.3.4 port 22" {
		t.Fatalf("record was not reassembled correctly: %q", got[0])
	}
}

func TestAssemblerBoundsOverlongLine(t *testing.T) {
	const maxLine = 64
	a := NewAssembler(maxLine, 4096)

	long := strings.Repeat("A", 4096)
	a.Feed(long + " tail\n")
	got := a.Flush()
	if len(got) != 1 {
		t.Fatalf("expected 1 record, got %d", len(got))
	}
	if !strings.Contains(got[0], "[line truncated]") {
		t.Error("overlong line must be marked truncated")
	}
	if len(got[0]) > maxLine+len(" [line truncated]") {
		t.Errorf("record length %d exceeds bound", len(got[0]))
	}
}

func TestAssemblerBoundsMultilineRecord(t *testing.T) {
	const maxRecord = 256
	a := NewAssembler(200, maxRecord)

	var b strings.Builder
	b.WriteString("header line\n")
	for i := 0; i < 100; i++ {
		b.WriteString(" continuation\n")
	}
	b.WriteString("next record\n")

	got := a.Feed(b.String())
	got = append(got, a.Flush()...)
	if len(got) != 2 {
		t.Fatalf("expected 2 records, got %d", len(got))
	}
	if len(got[0]) > maxRecord {
		t.Errorf("assembled record length %d exceeds max %d", len(got[0]), maxRecord)
	}
}

func TestAssemblerFlushReturnsPending(t *testing.T) {
	a := NewAssembler(1024, 4096)
	if got := a.Feed("trailing record without newline"); len(got) != 0 {
		t.Fatalf("Feed() = %#v, want no records", got)
	}
	got := a.Flush()
	if len(got) != 1 || got[0] != "trailing record without newline" {
		t.Fatalf("Flush() = %#v", got)
	}
	if again := a.Flush(); again != nil {
		t.Fatalf("second Flush() = %#v, want nil", again)
	}
}
