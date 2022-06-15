package ecdsa

import (
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"math/big"
	"testing"
)

func TestKey(t *testing.T) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		t.Error(err)
		return
	}
	pubKey := NewPublicKey(&privateKey.PublicKey)

	message := "hello world"
	t.Log("message", message)
	messageX, messageY := EncodeMessage([]byte(message))
	t.Logf("messageX:%s, messageY:%s", hex.EncodeToString(messageX.Bytes()), hex.EncodeToString(messageY.Bytes()))

	cipher, err := pubKey.Encrypt(messageX, messageY)
	if err != nil {
		t.Error(err)
		return
	}
	privKey := NewPrivateKey(privateKey)
	decryptX, decryptY, err := privKey.Decrypt(cipher)
	if err != nil {
		t.Error(err)
		return
	}
	t.Logf("decryptX:%s, decryptY:%s", hex.EncodeToString(decryptX.Bytes()), hex.EncodeToString(decryptY.Bytes()))
	messageByte := DecodeMessage(decryptX, decryptY)
	message = string(messageByte)
	t.Log("message:", message)
}

func TestCruve(t *testing.T) {
	P1 := new(big.Int).SetInt64(100)

	P2 := new(big.Int).SetInt64(200)

	//calc P3 = P1 + P2 => P1 = P3 + -1*P2
	P1X, P1Y := secp256k1.S256().ScalarBaseMult(P1.Bytes())
	t.Log(fmt.Sprintf("P1:(%s,%s)", P1X.String(), P1Y.String()))
	P2X, P2Y := secp256k1.S256().ScalarBaseMult(P2.Bytes())
	t.Log(fmt.Sprintf("P2:(%s,%s)", P2X.String(), P2Y.String()))

	P3X, P3Y := secp256k1.S256().Add(P1X, P1Y, P2X, P2Y)
	t.Log(fmt.Sprintf("P3:(%s,%s)", P3X.String(), P3Y.String()))

	P1_X, P1_Y := secp256k1.S256().Add(P3X, P3Y, P2X, new(big.Int).Neg(P2Y))
	t.Log(fmt.Sprintf("P1_:(%s,%s)", P1_X.String(), P1_Y.String()))
}

func TestCurveMul(t *testing.T) {
	r, _ := crypto.GenerateKey() //rand Num
	d, _ := crypto.GenerateKey() //privKey
	m, _ := crypto.GenerateKey() //use publicKey as Message

	Mx, My := m.PublicKey.X, m.PublicKey.Y
	Gx, Gy := secp256k1.S256().Params().Gx, secp256k1.S256().Params().Gy
	Qx, Qy := d.PublicKey.X, d.PublicKey.Y
	t.Log("M", Mx.String(), My.String())
	t.Log("Q", Qx, Qy)

	//dG
	dGx, dGy := secp256k1.S256().ScalarMult(Gx, Gy, d.D.Bytes())
	t.Log("dG", dGx.String(), dGy.String())

	//calc rQ
	rQx, rQy := secp256k1.S256().ScalarMult(Qx, Qy, r.D.Bytes())
	t.Log("rQ", rQx.String(), rQy.String())

	rGx, rGy := secp256k1.S256().ScalarMult(Gx, Gy, r.D.Bytes())

	//calc d(rG)
	drGx, drGy := secp256k1.S256().ScalarMult(rGx, rGy, d.D.Bytes())
	t.Log("drG", drGx.String(), drGy.String())

	//calc r(dG)
	rdGx, rdGy := secp256k1.S256().ScalarMult(dGx, dGy, r.D.Bytes())
	t.Log("rdG", rdGx.String(), rdGy.String())

	// M + rdG
	MrdGx, MrdGy := secp256k1.S256().Add(Mx, My, rdGx, rdGy)

	//M + rdG - rQ
	Mrrx, Mrry := secp256k1.S256().Add(MrdGx, MrdGy, rQx, new(big.Int).Neg(rQy))
	t.Log("M + rdG - rQ", Mrrx.String(), Mrry.String())

	t.Logf("M + rQ - rQ == M?, cmp X: %d ,cmp Y:%d", Mrrx.Cmp(Mx), Mrry.Cmp(My))
}
