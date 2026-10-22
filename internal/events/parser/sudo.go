package parser

import (
	"regexp"
	"strings"

	"github.com/halimi/halimisoc/internal/events/model"
)

// SudoParser parses sudo audit records from auth.log / secure.
type SudoParser struct{}

// Name implements Parser.
func (p *SudoParser) Name() string { return "sudo" }

var (
	// Example:
	//   Aug 19 11:22:01 host sudo:   alice : TTY=pts/0 ; PWD=/home/alice ;
	//   USER=root ; COMMAND=/usr/bin/cat /etc/shadow
	reSudoCommand = regexp.MustCompile(
		`^(\S+)\s*:\s*TTY=(\S+)\s*;\s*PWD=(\S*)\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.*)$`)

	// Example: Aug 19 11:22:01 host sudo: pam_unix(sudo:auth): authentication failure; logname=alice uid=1000 ... user=alice
	reSudoAuthFail = regexp.MustCompile(
		`pam_unix\(sudo:auth\): authentication failure;.*?(?:user=(\S+))?`)

	// Example: Aug 19 11:22:01 host sudo: alice : 3 incorrect password attempts ; TTY=pts/0 ; ...
	reSudoIncorrect = regexp.MustCompile(`^(\S+)\s*:\s*(\d+) incorrect password attempts`)
)

// Match implements Parser.
func (p *SudoParser) Match(raw string) bool {
	_, _, msg := splitSyslogPrefix(raw)
	program, _, _ := splitProgram(msg)
	return program == "sudo"
}

// Parse implements Parser.
func (p *SudoParser) Parse(l Line) Result {
	ts, _, msg := splitSyslogPrefix(l.Raw)
	program, pid, body := splitProgram(msg)
	if program != "sudo" {
		return Result{Status: StatusUnsupported, Reason: "not a sudo record"}
	}

	at, ok := ParseTime(ts, l.ObservedAt)
	if !ok {
		at = l.ObservedAt
	}

	body = strings.TrimSpace(body)

	switch {
	case reSudoCommand.MatchString(body):
		m := reSudoCommand.FindStringSubmatch(body)
		e := baseEvent(l, model.TypeSudoCommand, at, model.SeverityMedium)
		e.Source = model.SourceAuthLog
		e.Actor = m[1]
		e.Target = m[4]
		e.Outcome = model.OutcomeSuccess
		e.Message = "sudo command executed"
		e.Attributes["tty"] = m[2]
		e.Attributes["pwd"] = m[3]
		e.Attributes["runas"] = m[4]
		e.Attributes["command"] = strings.TrimSpace(m[5])
		e.Attributes["command_binary"] = firstField(m[5])

		// A privileged command that rewrites authorized_keys is a persistence
		// action, not merely privilege escalation. The signal is recorded as an
		// attribute so the sudo event remains the privilege-escalation evidence
		// while a separate rule can match the persistence attempt.
		if cmd := strings.ToLower(m[5]); strings.Contains(cmd, "authorized_keys") {
			e.Attributes["file"] = "authorized_keys"
			e.Attributes["authorized_keys_modified"] = "true"
			e.Severity = model.SeverityCritical
		}
		if pid != "" {
			e.Attributes["pid"] = pid
		}
		if !ok {
			e.Attributes["timestamp_source"] = "observed"
		}
		return Result{Status: StatusValid, Event: e}

	case reSudoIncorrect.MatchString(body):
		m := reSudoIncorrect.FindStringSubmatch(body)
		e := baseEvent(l, model.TypeSudoAuthFailed, at, model.SeverityHigh)
		e.Source = model.SourceAuthLog
		e.Actor = m[1]
		e.Target = m[1]
		e.Outcome = model.OutcomeFailure
		e.Message = "sudo authentication failed"
		e.Attributes["attempts"] = m[2]
		if !ok {
			e.Attributes["timestamp_source"] = "observed"
		}
		return Result{Status: StatusValid, Event: e}

	case reSudoAuthFail.MatchString(body):
		m := reSudoAuthFail.FindStringSubmatch(body)
		e := baseEvent(l, model.TypeSudoAuthFailed, at, model.SeverityHigh)
		e.Source = model.SourceAuthLog
		user := ""
		if len(m) > 1 {
			user = m[1]
		}
		if user == "" {
			// Fall back to the logname= field, which is present even when
			// user= is missing.
			if i := strings.Index(body, "logname="); i >= 0 {
				user = firstField(body[i+len("logname="):])
			}
		}
		e.Actor = user
		e.Target = user
		e.Outcome = model.OutcomeFailure
		e.Message = "sudo authentication failed"
		if !ok {
			e.Attributes["timestamp_source"] = "observed"
		}
		return Result{Status: StatusValid, Event: e}
	}

	return Result{Status: StatusNonSecurityRelevant, Reason: "unmodeled sudo record"}
}

func firstField(s string) string {
	f := strings.Fields(strings.TrimSpace(s))
	if len(f) == 0 {
		return ""
	}
	return f[0]
}
