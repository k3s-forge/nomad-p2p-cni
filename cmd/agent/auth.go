package main

import (
	"crypto/hmac"
	"crypto/sha256"
)

func hmacSign(psk string, data []byte) []byte {
	mac := hmac.New(sha256.New, []byte(psk))
	mac.Write(data)
	return mac.Sum(nil)
}

func hmacVerify(psk string, data, sig []byte) bool {
	expected := hmacSign(psk, data)
	return hmac.Equal(expected, sig)
}
