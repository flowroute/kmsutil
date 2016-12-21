// Copyright © 2016 Flowroute Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package stash

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	keyLength   = 32
	nonceLength = 24
)

var (
	ErrorBoxOpenFail = errors.New("Unable to open secret box")
	ErrorBadVersion  = errors.New("Unknown secret box version")
)

type Payload struct {
	Version int
	Key     []byte
	Message []byte
}

type Stash struct {
	kc     kmsiface.KMSAPI
	P      Payload
	keyId  string
	noncer Noncer
}

func NewStash(key string, region string) (*Stash, error) {
	s := &Stash{}

	creds, err := session.NewSession()
	if err != nil {
		return nil, err
	}
	s.kc = kms.New(creds, &aws.Config{Region: aws.String(region)})
	s.keyId = key
	s.noncer = RandomNoncer{}

	return s, nil
}

func (s *Stash) Encrypt(plaintext []byte) ([]byte, error) {
	rsp, err := s.kc.GenerateDataKey(&kms.GenerateDataKeyInput{
		KeyId:         aws.String(s.keyId),
		NumberOfBytes: aws.Int64(keyLength),
	})
	if err != nil {
		return nil, err
	}

	// Create key
	key := &[keyLength]byte{}
	copy(key[:], rsp.Plaintext)

	// Get a nonce.
	nonce, err := s.noncer.Nonce()
	if err != nil {
		return nil, err
	}

	// Start our message with a copy of the nonce.
	out := make([]byte, nonceLength)
	copy(out, nonce[:])

	// Encrypt our message text
	message := secretbox.Seal(out, plaintext, nonce, key)

	s.P = Payload{
		Version: 1,
		Key:     rsp.CiphertextBlob,
		Message: message,
	}

	buf := &bytes.Buffer{}
	if err := json.NewEncoder(buf).Encode(s.P); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (s *Stash) Decrypt(ciphertext []byte) ([]byte, error) {
	buf := bytes.NewBuffer(ciphertext)
	// Decode ciphertext with json
	json.NewDecoder(buf).Decode(&s.P)
	if s.P.Version != 1 {
		return nil, ErrorBadVersion
	}

	// Decrypt key
	decryptRsp, err := s.kc.Decrypt(&kms.DecryptInput{
		CiphertextBlob: s.P.Key,
	})
	if err != nil {
		return nil, err
	}
	key := &[keyLength]byte{}
	copy(key[:], decryptRsp.Plaintext)

	// Decrypt message
	var plaintext []byte
	var nonce [nonceLength]byte
	copy(nonce[:], s.P.Message[:nonceLength])
	plaintext, ok := secretbox.Open(plaintext, s.P.Message[nonceLength:], &nonce, key)
	if !ok {
		return nil, ErrorBoxOpenFail
	}
	return plaintext, nil
}
