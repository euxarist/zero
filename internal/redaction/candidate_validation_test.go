package redaction

import "testing"

type countingCandidatePattern struct {
	calls int
}

func (p *countingCandidatePattern) MatchString(string) bool {
	p.calls++
	return true
}

func TestAcceptedCandidateIsValidatedOnce(t *testing.T) {
	// A toy shape isolates validation cost from production credential patterns.
	// Each gap extends the same accepted candidate; no prefix needs rechecking.
	input := "sample\x00a\x00b\x00c"
	pattern := &countingCandidatePattern{}
	shape := secretShape{plainPattern: pattern, minLen: 1}
	spans, consumed := extractSpansFromMatch(input, 0, len(input), shape, false)
	if len(spans) != 1 || spans[0] != (span{start: 0, end: len(input)}) || consumed != len(input) {
		t.Fatalf("candidate coverage = %v, consumed = %d", spans, consumed)
	}
	if pattern.calls != 1 {
		t.Fatalf("validated the same accepted candidate %d times, want 1", pattern.calls)
	}
}
