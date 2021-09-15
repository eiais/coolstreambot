package main

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetCoolHeaderNoHeader(t *testing.T) {
	headers := http.Header{
		"a": []string{"1"},
	}
	val, err := getCoolHeader("b", headers)
	assert.Contains(t, err.Error(), "missing header")
	assert.Equal(t, val, "")
}

func TestGetCoolHeaderTooMuchHeader(t *testing.T) {
	headers := http.Header{
		"a": []string{"1", "2"},
	}
	val, err := getCoolHeader("a", headers)
	assert.Contains(t, err.Error(), "too many headers")
	assert.Equal(t, val, "")
}

func TestGetCoolHeaderValidHeader(t *testing.T) {
	headers := http.Header{
		"a": []string{"1"},
	}
	val, err := getCoolHeader("a", headers)
	assert.Nil(t, err)
	assert.Equal(t, val, "1")
}

func TestRewardFromStringExists(t *testing.T) {
	reward := rewardFromString("lights")
	assert.Equal(t, reward, lights)
}

func TestRewardFromStringUnknown(t *testing.T) {
	reward := rewardFromString("nonexistant reward")
	assert.Equal(t, reward, unknown)
}

func TestVerifyWebhookNoSignature(t *testing.T) {
	rewards := verifyWebhook(http.Header{}, []byte{}, []hmacKey{})
	assert.Nil(t, rewards)
}

func TestVerifyWebhookInvalidSignature(t *testing.T) {
	header := http.Header{
		signatureHeader: []string{"invalid signature"},
	}
	rewards := verifyWebhook(header, []byte{}, []hmacKey{})
	assert.Nil(t, rewards)
}
func TestVerifyWebhookInvalidSignatureHex(t *testing.T) {
	header := http.Header{
		signatureHeader: []string{"sha256=invalidhex"},
	}
	rewards := verifyWebhook(header, []byte{}, []hmacKey{})
	assert.Nil(t, rewards)
}

func TestVerifyWebhookNoTimestamp(t *testing.T) {
	header := http.Header{
		signatureHeader: []string{"sha256=1c5863cd55b5a4413fd59f054af57ba3c75c0698b3851d70f99b8de2d5c7338f"},
	}
	rewards := verifyWebhook(header, []byte{}, []hmacKey{})
	assert.Nil(t, rewards)
}

func TestVerifyWebhookNoMsgId(t *testing.T) {
	header := http.Header{
		signatureHeader: []string{"sha256=1c5863cd55b5a4413fd59f054af57ba3c75c0698b3851d70f99b8de2d5c7338f"},
		timestampHeader: []string{"this is a timestamp"},
	}
	rewards := verifyWebhook(header, []byte{}, []hmacKey{})
	assert.Nil(t, rewards)
}

func TestVerifyWebhookNoHmacKey(t *testing.T) {
	header := http.Header{
		signatureHeader: []string{"sha256=1c5863cd55b5a4413fd59f054af57ba3c75c0698b3851d70f99b8de2d5c7338f"},
		timestampHeader: []string{"this is a timestamp"},
		msgIdHeader:     []string{"this is a message id"},
	}
	rewards := verifyWebhook(header, []byte{}, []hmacKey{})
	assert.Nil(t, rewards)
}

func TestVerifyWebhookIncorrectSignature(t *testing.T) {
	header := http.Header{
		signatureHeader: []string{"sha256=1c5863cd55b5a4413fd59f054af57ba3c75c0698b3851d70f99b8de2d5c7338f"},
		timestampHeader: []string{"this is a timestamp"},
		msgIdHeader:     []string{"this is a message id"},
	}
	requstBody := []byte("this is a body")
	testKey := []hmacKey{
		{
			secret:      []byte("test"),
			permissions: []reward{},
		},
	}
	rewards := verifyWebhook(header, requstBody, testKey)
	assert.Nil(t, rewards)
}

func TestVerifyWebhookNoPermissions(t *testing.T) {
	header := http.Header{
		signatureHeader: []string{"sha256=978cd8799146219e88be1f2d0079e59c85b89dbbd21b9e163b0f8bb926377af9"},
		timestampHeader: []string{"this is a timestamp"},
		msgIdHeader:     []string{"this is a message id"},
	}
	requstBody := []byte("this is a body")
	testKey := []hmacKey{
		{
			secret:      []byte("test"),
			permissions: []reward{},
		},
	}
	rewards := verifyWebhook(header, requstBody, testKey)
	assert.Equal(t, rewards, []reward{})
}

func TestVerifyWebhookPermissions(t *testing.T) {
	header := http.Header{
		signatureHeader: []string{"sha256=978cd8799146219e88be1f2d0079e59c85b89dbbd21b9e163b0f8bb926377af9"},
		timestampHeader: []string{"this is a timestamp"},
		msgIdHeader:     []string{"this is a message id"},
	}
	requstBody := []byte("this is a body")
	testKey := []hmacKey{
		{
			secret:      []byte("test"),
			permissions: []reward{scrollo},
		},
	}
	rewards := verifyWebhook(header, requstBody, testKey)
	assert.Equal(t, rewards, []reward{scrollo})
}
