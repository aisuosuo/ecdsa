package ecdsa

import (
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"
	"testing"
)

var (
	Message       = "王丰鞍山市啊爱上爱上爱上爱上爱上撒撒撒算法"
	TmpPrivateKey = "4b4966191bae34e99a41085d4ff7a244f12e25b67be5507064d4f0e3bb378d45"
	TmpPublicKey  = "03c70d10ac413249c55ff39faa3fa92eaa44c79ed3749913232b52a704906c5417"
)

func TestCrypto(t *testing.T) {
	//encrypt
	publicKeyHex := TmpPublicKey
	publicKey, err := NewPublicKeyFromHex(publicKeyHex)
	if err != nil {
		t.Error(err)
		return
	}

	t.Log(len([]byte(Message)))

	mx, my, err := EncodeMessage([]byte(Message))
	if err != nil {
		t.Error(err)
		return
	}
	encrypt, err := publicKey.Encrypt(mx, my)
	if err != nil {
		t.Error(err)
		return
	}
	messageHex := hex.EncodeToString(encrypt)

	//decrypt
	privkeyHex := TmpPrivateKey
	ciphertext, err := hex.DecodeString(messageHex)
	if err != nil {
		t.Error(err)
		return
	}
	privkey, err := NewPrivateKeyFromHex(privkeyHex)
	if err != nil {
		t.Error(err)
		return
	}
	mx, my, err = privkey.Decrypt(ciphertext)
	if err != nil {
		t.Error(err)
		return
	}
	decodeMessage := DecodeMessage(mx, my)
	t.Log("decodeMessage:", string(decodeMessage))
	t.Log("decodeMessage cmp message:", string(decodeMessage) == Message)
}

func TestCrypto2(t *testing.T) {
	privKey, err := GeneratePrivateKey()
	if err != nil {
		t.Error(err)
		return
	}
	pubKey := privKey.Public()

	message := "hello world"
	t.Log("message:", message)
	messageX, messageY, err := EncodeMessage([]byte(message))
	if err != nil {
		t.Error(err)
		return
	}
	cipher, err := pubKey.Encrypt(messageX, messageY)
	if err != nil {
		t.Error(err)
		return
	}

	decryptX, decryptY, err := privKey.Decrypt(cipher)
	if err != nil {
		t.Error(err)
		return
	}
	messageByte := DecodeMessage(decryptX, decryptY)
	message = string(messageByte)
	t.Log("decrypt message:", message)
}

func TestGenerateKey(t *testing.T) {
	privateKey, err := GeneratePrivateKey()
	if err != nil {
		t.Error(err)
		return
	}
	t.Log("privateKey:", hex.EncodeToString(crypto.FromECDSA(privateKey.PrivateKey)))
	t.Log("publicKey:", hex.EncodeToString(crypto.CompressPubkey(privateKey.Public().PublicKey)))
	//privateKey: 4b4966191bae34e99a41085d4ff7a244f12e25b67be5507064d4f0e3bb378d45
	//publicKey: 03c70d10ac413249c55ff39faa3fa92eaa44c79ed3749913232b52a704906c5417
}

func TestCruve(t *testing.T) {
	P1 := new(big.Int).SetInt64(100)

	P2 := new(big.Int).SetInt64(200)

	//calc P3 = P1 + P2 => P1 = P3 + -1*P2
	P1X, P1Y := Curve.ScalarBaseMult(P1.Bytes())
	t.Log(fmt.Sprintf("P1:(%s,%s)", P1X.String(), P1Y.String()))
	P2X, P2Y := Curve.ScalarBaseMult(P2.Bytes())
	t.Log(fmt.Sprintf("P2:(%s,%s)", P2X.String(), P2Y.String()))

	P3X, P3Y := Curve.Add(P1X, P1Y, P2X, P2Y)
	t.Log(fmt.Sprintf("P3:(%s,%s)", P3X.String(), P3Y.String()))

	P1_X, P1_Y := Curve.Add(P3X, P3Y, P2X, new(big.Int).Neg(P2Y))
	t.Log(fmt.Sprintf("P1_:(%s,%s)", P1_X.String(), P1_Y.String()))
}

func TestCurveMul(t *testing.T) {
	r, _ := crypto.GenerateKey() //rand Num
	d, _ := crypto.GenerateKey() //privKey
	m, _ := crypto.GenerateKey() //use publicKey as Message

	Mx, My := m.PublicKey.X, m.PublicKey.Y
	Gx, Gy := Curve.Params().Gx, Curve.Params().Gy
	Qx, Qy := d.PublicKey.X, d.PublicKey.Y
	t.Log("M", Mx.String(), My.String())
	t.Log("Q", Qx, Qy)

	//dG
	dGx, dGy := Curve.ScalarMult(Gx, Gy, d.D.Bytes())
	t.Log("dG", dGx.String(), dGy.String())

	//calc rQ
	rQx, rQy := Curve.ScalarMult(Qx, Qy, r.D.Bytes())
	t.Log("rQ", rQx.String(), rQy.String())

	rGx, rGy := Curve.ScalarMult(Gx, Gy, r.D.Bytes())

	//calc d(rG)
	drGx, drGy := Curve.ScalarMult(rGx, rGy, d.D.Bytes())
	t.Log("drG", drGx.String(), drGy.String())

	//calc r(dG)
	rdGx, rdGy := Curve.ScalarMult(dGx, dGy, r.D.Bytes())
	t.Log("rdG", rdGx.String(), rdGy.String())

	// M + rdG
	MrdGx, MrdGy := Curve.Add(Mx, My, rdGx, rdGy)

	//M + rdG - rQ
	Mrrx, Mrry := Curve.Add(MrdGx, MrdGy, rQx, new(big.Int).Neg(rQy))
	t.Log("M + rdG - rQ", Mrrx.String(), Mrry.String())

	t.Logf("M + rQ - rQ == M?, cmp X: %d ,cmp Y:%d", Mrrx.Cmp(Mx), Mrry.Cmp(My))
}
