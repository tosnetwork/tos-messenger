//go:build !linux

package attachments

import (
	"errors"
	"os"
)

func newSealedScanInput([]byte) (*os.File, error) {
	return nil, errors.New("sealed attachment scanner input requires Linux")
}
