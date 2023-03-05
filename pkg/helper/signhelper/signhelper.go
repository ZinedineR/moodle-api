package signhelper

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"moodle-api/pkg/data/constant"
	"moodle-api/pkg/errs"

	"github.com/sirupsen/logrus"
)

func RsaSign(signContent string, privateKey string, hash crypto.Hash) (string, error) {

	shaNew := hash.New()
	shaNew.Write([]byte(signContent))
	hashed := shaNew.Sum(nil)
	priKey, err := ParsePrivateKey(privateKey)
	if err != nil {
		return "", err
	}

	signature, err := rsa.SignPKCS1v15(rand.Reader, priKey, hash, hashed)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

func SignHMAC512(clientSecret, stringToSign string) string {

	// --- hmac sha512 hasher with client secret as key
	h_sha := hmac.New(crypto.SHA512.New, []byte(clientSecret))
	h_sha.Write([]byte(stringToSign))
	// ---

	signature := hex.EncodeToString(h_sha.Sum(nil))
	return signature
}

func SignHMAC256(clientSecret, stringToSign string) string {

	// --- hmac sha512 hasher with client secret as key
	h_sha := hmac.New(crypto.SHA256.New, []byte(clientSecret))
	h_sha.Write([]byte(stringToSign))
	// ---

	signature := hex.EncodeToString(h_sha.Sum(nil))
	return signature
}

func VerifyHMAC512(stringToSign, clientSecret []byte, hash string) (bool, error) {
	mac := hmac.New(sha512.New, clientSecret)
	mac.Write(stringToSign)
	sig, err := hex.DecodeString(hash)
	if err != nil {
		logrus.Errorln(fmt.Sprintf("RESPONSE: response_code: 401 error: Signature Invalid, Request Signature should be: %s", hex.EncodeToString(mac.Sum(nil))))
		return false, err
	}

	if !hmac.Equal(sig, mac.Sum(nil)) {
		logrus.Errorln(fmt.Sprintf("RESPONSE: response_code: 401 error: Signature Invalid, Request Signature should be: %s", hex.EncodeToString(mac.Sum(nil))))
	}

	return hmac.Equal(sig, mac.Sum(nil)), nil
}

func ParsePrivateKey(privateKey string) (*rsa.PrivateKey, error) {

	privateKey = FormatPrivateKey(privateKey)

	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {

		return nil, errors.New("private key invalid！")
	}

	priKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {

		return nil, err
	}
	return priKey, nil
}

func ParsePublicKey(publicKey string) (*rsa.PublicKey, error) {

	publicKey = FormatPublicKey(publicKey)

	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {

		return nil, errors.New("private key invalid！")
	}

	pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {

		return nil, err
	}
	return pubKey, nil
}

func FormatPrivateKey(privateKey string) string {

	if !strings.HasPrefix(privateKey, constant.PEM_BEGIN) {

		privateKey = constant.PEM_BEGIN + privateKey
	}
	if !strings.HasSuffix(privateKey, constant.PEM_END) {

		privateKey = privateKey + constant.PEM_END
	}
	return privateKey
}

func FormatPublicKey(publicKey string) string {

	if !strings.HasPrefix(publicKey, constant.PUB_BEGIN) {

		publicKey = constant.PUB_BEGIN + publicKey
	}
	if !strings.HasSuffix(publicKey, constant.PUB_END) {

		publicKey = publicKey + constant.PUB_END
	}
	return publicKey
}

func GenerateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, errs.Error) {
	privatekey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, errs.Wrap(err)
	}
	return privatekey, &privatekey.PublicKey, nil
}

func ExportRsaPrivateKeyAsPemStr(privateKey *rsa.PrivateKey) string {
	privateKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		},
	)
	return string(privateKeyPem)
}

func ExportRsaPublicKeyAsPemStr(pubKey *rsa.PublicKey) string {
	pubKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(pubKey),
		},
	)
	return string(pubKeyPem)
}

func EncryptAES(text []byte) (string, error) {

	block, err := aes.NewCipher([]byte(os.Getenv("PAYLOAD_KEY")))
	if err != nil {
		return "", err
	}
	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	data := hex.EncodeToString(ciphertext)
	return data, nil
}

func DecryptAES(text string) (string, error) {
	hexData, err := hex.DecodeString(text)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher([]byte(os.Getenv("PAYLOAD_KEY")))
	if err != nil {
		return "", err
	}
	if len(hexData) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	iv := hexData[:aes.BlockSize]
	hexData = hexData[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(hexData, hexData)
	data, err := base64.StdEncoding.DecodeString(string(hexData))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s\n", data), nil
}

func CheckError(err error) {
	if err != nil {
		panic(err)
	}
}
