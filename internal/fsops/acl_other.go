//go:build !linux

package fsops

// Off Linux there are no POSIX or NFSv4 ACL extended attributes to read, and
// nothing here stages anything either (stagedCreate is false), so the question
// is never asked. Answering "nothing grants anybody anything" rather than
// refusing keeps the dev loop honest about what it does not know: it is the
// same documented degradation as every other identity question here (INV-2).
func aclFactsFor(d *dirRef) (aclFacts, error) {
	_ = d
	return aclFacts{}, nil
}
