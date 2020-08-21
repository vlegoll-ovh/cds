package encryption

import (
	"fmt"
	"io"

	"github.com/ovh/symmecrypt/convergent"

	"github.com/ovh/cds/engine/cdn/index"
	"github.com/ovh/cds/sdk"
)

func New(config []convergent.ConvergentEncryptionConfig) *ConvergentEncryption {
	return &ConvergentEncryption{config: config}
}

type ConvergentEncryption struct {
	k      convergent.Key
	config []convergent.ConvergentEncryptionConfig
}

func (s *ConvergentEncryption) getKey(h string) (convergent.Key, error) {
	if s.k == nil {
		fmt.Println(h)
		k, err := convergent.NewKey(h, s.config...)
		if err != nil {
			return nil, sdk.WithStack(err)
		}
		s.k = k
	}
	return s.k, nil
}

func (s *ConvergentEncryption) NewLocator(h string) (string, error) {
	k, err := s.getKey(h)
	if err != nil {
		return "", err
	}
	return k.Locator()
}

func (s *ConvergentEncryption) Write(i index.Item, r io.Reader, w io.Writer) error {
	k, err := s.getKey(i.Hash)
	if err != nil {
		return err
	}
	err = k.EncryptPipe(r, w, []byte(i.ID))
	return sdk.WrapError(err, "[%T] unable to write item %s", s, i.ID)
}

func (s *ConvergentEncryption) Read(i index.Item, r io.Reader, w io.Writer) error {
	k, err := s.getKey(i.Hash)
	if err != nil {
		return err
	}
	err = k.DecryptPipe(r, w, []byte(i.ID))
	return sdk.WrapError(err, "[%T] unable to read item %s", s, i.ID)
}
