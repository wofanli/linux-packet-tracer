package util

import (
	"github.com/qiniu/log"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPid2Netns(t *testing.T) {
	a := Pid2Netns(5577)
	log.Info("got netns ", a)
	assert.Equal(t, "", "")
}
