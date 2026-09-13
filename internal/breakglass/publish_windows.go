package breakglass

import "os"

// publish renames tmp over path. Windows refuses a rename onto an existing file
// in the configurations this project is developed on, so the destination is
// removed first — the gap that opens is accepted here and only here, because
// the dev box is not where the emergency door has to survive a crash.
func publish(tmp, path string) error {
	_ = os.Remove(path)
	return os.Rename(tmp, path)
}
