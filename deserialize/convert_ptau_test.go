package deserializer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConvertPtau(t *testing.T) {
	ptau, err := ReadPtau("08.ptau")
	assert.NoError(t, err)

	_, err = ConvertPtauToPhase1(ptau)
	assert.NoError(t, err)
}
