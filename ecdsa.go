package ecdsa

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"math/big"
)

type PrivateKey struct {
	*ecdsa.PrivateKey
}

type PublicKey struct {
	*ecdsa.PublicKey
}

func NewPrivateKey(key *ecdsa.PrivateKey) PrivateKey {
	return PrivateKey{
		key,
	}
}

func NewPublicKey(key *ecdsa.PublicKey) PublicKey {
	return PublicKey{
		key,
	}
}

func EncodeMessage(message []byte) (x, y *big.Int) {
	length := len(message)
	x = new(big.Int).SetBytes(message[:length/2])
	y = new(big.Int).SetBytes(message[length/2:])
	return
}

func DecodeMessage(x, y *big.Int) []byte {
	return bytes.Join([][]byte{x.Bytes(), y.Bytes()}, nil)
}

// Encrypt encrypt:C = {rG, M+rQ}, decrypt:M+rQ-d(rG) = M+r(dG)-d(rG) = M
func (p *PublicKey) Encrypt(x, y *big.Int) ([]byte, error) {
	//get rG,M(x,y)+rQ
	r, err := ecdsa.GenerateKey(p.Curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	Qx, Qy := p.X, p.Y
	rGx, rGy := p.Curve.ScalarBaseMult(r.D.Bytes())
	rQx, rQy := p.Curve.ScalarMult(Qx, Qy, r.D.Bytes())

	//M(x,y)+rQ
	mrQx, mrQy := p.Curve.Add(x, y, rQx, rQy)
	b := make([]byte, 0, 128)
	b = paddedAppend(32, b, rGx.Bytes())
	b = paddedAppend(32, b, rGy.Bytes())
	b = paddedAppend(32, b, mrQx.Bytes())
	return paddedAppend(32, b, mrQy.Bytes()), nil
}

func paddedAppend(size uint, dst, src []byte) []byte {
	for i := 0; i < int(size)-len(src); i++ {
		dst = append(dst, 0)
	}
	return append(dst, src...)
}

// Decrypt encrypt:C = {rG, M+rQ}, decrypt:M+rQ-d(rG) = M+r(dG)-d(rG) = M
func (p *PrivateKey) Decrypt(ciphertext []byte) (x, y *big.Int, err error) {
	if len(ciphertext) != 128 {
		err = errors.New("ciphertext not right")
		return
	}
	rGx := new(big.Int).SetBytes(ciphertext[:32])
	rGy := new(big.Int).SetBytes(ciphertext[32:64])
	mrQx := new(big.Int).SetBytes(ciphertext[64:96])
	mrQy := new(big.Int).SetBytes(ciphertext[96:128])

	//d(rG)
	drGx, drGy := p.Curve.ScalarMult(rGx, rGy, p.D.Bytes())
	//M+rQ - d(rG) = (M+r(dG)-d(rG)) = M
	x, y = p.Curve.Add(mrQx, mrQy, drGx, new(big.Int).Neg(drGy))
	return
}
