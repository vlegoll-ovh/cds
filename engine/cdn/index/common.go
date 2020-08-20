package index

import (
	"strconv"

	"github.com/mitchellh/hashstructure"

	"github.com/ovh/cds/sdk"
)

func ComputeApiRef(x ApiRef) (string, error) {
	hashRefU, err := hashstructure.Hash(x, nil)
	if err != nil {
		return "", sdk.WithStack(err)
	}
	hashRef := strconv.FormatUint(hashRefU, 10)
	return hashRef, nil
}
