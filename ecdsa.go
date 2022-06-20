package ecdsa

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"math/big"
)

var Curve = secp256k1.S256()

type PrivateKey struct {
	*ecdsa.PrivateKey
}

type PublicKey struct {
	*ecdsa.PublicKey
}

func GeneratePrivateKey() (*PrivateKey, error) {
	key, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}
	return &PrivateKey{
		key,
	}, nil
}

func NewPrivateKeyFromKey(key *ecdsa.PrivateKey) *PrivateKey {
	return &PrivateKey{
		key,
	}
}

func NewPublicKeyFromKey(key *ecdsa.PublicKey) *PublicKey {
	return &PublicKey{
		key,
	}
}

func NewPrivateKeyFromHex(privkeyHex string) (*PrivateKey, error) {
	key, err := crypto.HexToECDSA(privkeyHex)
	if err != nil {
		return nil, err
	}
	return NewPrivateKeyFromKey(key), nil
}

func NewPublicKeyFromHex(pubkeyHex string) (*PublicKey, error) {
	hexToBytes, err := hex.DecodeString(pubkeyHex)
	if err != nil {
		return nil, err
	}
	x, y := UnmarshalPublicKey(hexToBytes)
	key := &ecdsa.PublicKey{Curve: Curve, X: x, Y: y}
	return NewPublicKeyFromKey(key), nil
}

func UnmarshalPublicKey(data []byte) (x, y *big.Int) {
	curve := Curve
	byteLen := (curve.Params().BitSize + 7) / 8
	if len(data) == 1+2*byteLen {
		return elliptic.Unmarshal(curve, data)
	}
	if len(data) == 1+byteLen {
		return secp256k1.DecompressPubkey(data)
	}

	return
}

// EncodeMessage Encode plaintext as a point on an elliptic curve (you can customize this method)
func EncodeMessage(message []byte) (x, y *big.Int, err error) {
	length := len(message)
	if length > 64 {
		err = errors.New("message length exceed 64")
		return
	}
	x = new(big.Int).SetBytes(message[:length/2])
	y = new(big.Int).SetBytes(message[length/2:])
	return
}

// DecodeMessage Decode a point on an elliptic curve to plaintext (you can customize this method)
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

func (p *PrivateKey) Public() PublicKey {
	return PublicKey{
		&p.PrivateKey.PublicKey,
	}
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
