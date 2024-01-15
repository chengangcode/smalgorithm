package sm2

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"cryptobin/zbbank/sm3"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
	"math/big"
)

func EncryptByb4(pkey, m string) []byte {
	p, err := x509.ReadPublicKeyFromHex(pkey)
	if err != nil {
		panic(err)
	}

	d, err := encrypt(p, []byte(m))
	if err != nil {
		panic(err)
	}

	return d

}

func encrypt(publicKey *sm2.PublicKey, m []byte) ([]byte, error) {
	kLen := len(m)
	var C1, t []byte
	var err error
	var kx, ky *big.Int
	for {
		k, _ := rand.Int(rand.Reader, publicKey.Params().N)
		C1x, C1y := sm2.P256Sm2().ScalarBaseMult(k.Bytes())
		C1 = elliptic.Marshal(publicKey.Curve, C1x, C1y)

		kx, ky = publicKey.ScalarMult(publicKey.X, publicKey.Y, k.Bytes())
		kpbBytes := elliptic.Marshal(publicKey, kx, ky)
		t, err = kdf(kpbBytes, kLen)
		if err != nil {
			return nil, err
		}
		if !isAllZero(t) {
			break
		}
	}

	C2 := make([]byte, kLen)
	for i := 0; i < kLen; i++ {
		C2[i] = m[i] ^ t[i]
	}

	C3 := calculateHash(kx, m, ky)

	r := make([]byte, 0, len(C1)+len(C2)+len(C3))
	r = append(r, C1...)
	r = append(r, C2...)
	r = append(r, C3...)
	return r, nil
}

func isAllZero(m []byte) bool {
	for i := 0; i < len(m); i++ {
		if m[i] != 0 {
			return false
		}
	}
	return true
}

func DecryptByb4(key, pkey string) []byte {
	k, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		panic(err)
	}

	p, err := x509.ReadPrivateKeyFromHex(pkey)
	if err != nil {
		panic(err)
	}
	//fmt.Println(p)

	sk, err := decrypt(p, k)
	if err != nil {
		panic(err)
	}

	return sk
}

func DecryptByHex(data, pkey string) []byte {
	k, err := hex.DecodeString(data)
	if err != nil {
		panic(err)
	}

	p, err := x509.ReadPrivateKeyFromHex(pkey)
	if err != nil {
		panic(err)
	}
	//fmt.Println(p)

	sk, err := decrypt(p, k)
	if err != nil {
		panic(err)
	}

	return sk
}

func decrypt(privateKey *sm2.PrivateKey, encryptData []byte) ([]byte, error) {
	C1Byte := make([]byte, 65)
	copy(C1Byte, encryptData[:65])
	x, y := elliptic.Unmarshal(privateKey.Curve, C1Byte)

	dBC1X, dBC1Y := privateKey.Curve.ScalarMult(x, y, privateKey.D.Bytes())
	dBC1Bytes := elliptic.Marshal(privateKey.Curve, dBC1X, dBC1Y)

	kLen := len(encryptData) - 65 - 20
	t, err := kdf(dBC1Bytes, kLen)
	if err != nil {
		return nil, err
	}

	M := make([]byte, kLen)
	for i := 0; i < kLen; i++ {
		M[i] = encryptData[65+i] ^ t[i]
	}

	C3 := make([]byte, 20)
	copy(C3, encryptData[len(encryptData)-20:])
	u := calculateHash(dBC1X, M, dBC1Y)

	if bytes.Compare(u, C3) == 0 {
		return M, nil
	} else {
		return nil, errors.New("解密失败")
	}
}

func kdf(Z []byte, klen int) ([]byte, error) {
	ct := 1
	end := (klen + 31) / 32
	result := make([]byte, 0)
	for i := 1; i <= end; i++ {
		b, err := sm3.Sm3hash(Z, intToBytes(ct))
		if err != nil {
			return nil, err
		}
		result = append(result, b...)
		ct++
	}
	last, err := sm3.Sm3hash(Z, intToBytes(ct))
	if err != nil {
		return nil, err
	}
	if klen%32 == 0 {
		result = append(result, last...)
	} else {
		result = append(result, last[:klen%32]...)
	}
	return result, nil
}

func calculateHash(x *big.Int, M []byte, y *big.Int) []byte {
	digest := sha256.New()
	digest.Write(bigIntToByte(x))
	digest.Write(M)
	digest.Write(bigIntToByte(y))
	result := digest.Sum(nil)[:20]
	return result
}

func intToBytes(x int) []byte {
	var buf = make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(x))
	return buf
}

func bigIntToByte(n *big.Int) []byte {
	byteArray := n.Bytes()
	// If the most significant byte's most significant bit is set,
	// prepend a 0 byte to the slice to avoid being interpreted as a negative number.
	if (byteArray[0] & 0x80) != 0 {
		byteArray = append([]byte{0}, byteArray...)
	}
	return byteArray
}
