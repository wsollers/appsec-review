package fixture

import "os"

func overlyPermissive(path string) error {
	return os.Chmod(path, 0777)
}
