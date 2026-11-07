// Package kerberos implements the Quazal Rendez-Vous ticket scheme: RC4
// encryption with an appended HMAC-MD5, and MD5-iterated key derivation.
package kerberos

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"errors"
)

func md5n(k []byte, n int) []byte {
	for i := 0; i < n; i++ {
		s := md5.Sum(k)
		k = s[:]
	}
	return k
}

// InitialHash is what the game sends (hex encoded) when creating an
// account: MD5 applied 65000 times to the password.
func InitialHash(password []byte) []byte { return md5n(password, 65000) }

// DeriveFromInitial turns an initial hash into a player's Kerberos key.
func DeriveFromInitial(initial []byte, pid uint32) []byte { return md5n(initial, int(pid%1024)) }

// DeriveKey is Quazal's MD5KeyDerivation: MD5 applied 65000 + pid%1024
// times to the password.
func DeriveKey(password []byte, pid uint32) []byte {
	return DeriveFromInitial(InitialHash(password), pid)
}

func rc4xor(key, data []byte) []byte {
	c, err := rc4.NewCipher(key)
	if err != nil {
		panic(err)
	}
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)
	return out
}

// Encrypt returns RC4(key, data) followed by HMAC-MD5(key, ciphertext).
func Encrypt(key, data []byte) []byte {
	ct := rc4xor(key, data)
	m := hmac.New(md5.New, key)
	m.Write(ct)
	return m.Sum(ct)
}

// Decrypt checks the trailing HMAC-MD5 and returns the plaintext.
func Decrypt(key, data []byte) ([]byte, error) {
	if len(data) < md5.Size {
		return nil, errors.New("kerberos: data too short")
	}
	ct, mac := data[:len(data)-md5.Size], data[len(data)-md5.Size:]
	m := hmac.New(md5.New, key)
	m.Write(ct)
	if !hmac.Equal(mac, m.Sum(nil)) {
		return nil, errors.New("kerberos: bad HMAC")
	}
	return rc4xor(key, ct), nil
}

// DecryptNoMAC decrypts data that carries no HMAC.
func DecryptNoMAC(key, data []byte) []byte { return rc4xor(key, data) }
