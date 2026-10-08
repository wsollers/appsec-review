package fixture

import "os"

func restricted(path string) error {
	return os.Chmod(path, 0600)
}
