package message

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	ec "github.com/bitcoin-sv/go-sdk/primitives/ec"
)

// https://github.com/bitcoin-sv/BRCs/blob/master/peer-to-peer/0077.md
var VERSION_BYTES = []byte{0x42, 0x42, 0x33, 0x01}

type SignedMessage struct {
	Version            []byte
	SenderPublicKey    *ec.PublicKey
	RecipientPublicKey *ec.PublicKey
	KeyID              []byte
	Signature          *ec.Signature
}

func Sign(message []byte, signer *ec.PrivateKey, verifier *ec.PublicKey) ([]byte, error) {
	// 注意：调用此函数前，消息应该已经进行了 SHA256 哈希处理
	// TypeScript 实现在内部进行哈希处理，而 Go 实现则期望输入已经是哈希值

	recipientAnyone := verifier == nil
	if recipientAnyone {
		// 使用32字节大端序整数值1作为特殊私钥，符合BRC-77协议
		specialKey := make([]byte, 32)
		specialKey[31] = 1 // 大端序表示的整数1
		anyonePrivKey, _ := ec.PrivateKeyFromBytes(specialKey)
		verifier = anyonePrivKey.PubKey()
	}

	keyID := make([]byte, 32)
	_, err := rand.Read(keyID)
	if err != nil {
		return nil, err
	}
	keyIDBase64 := base64.StdEncoding.EncodeToString(keyID)
	invoiceNumber := "2-message signing-" + keyIDBase64
	// 使用正确的参数顺序调用DeriveChild方法
	signingPriv, err := signer.DeriveChild(verifier, invoiceNumber)
	if err != nil {
		return nil, err
	}
	signature, err := signingPriv.Sign(message)
	if err != nil {
		return nil, err
	}
	senderPublicKey := signer.PubKey()

	sig := append(VERSION_BYTES, senderPublicKey.Compressed()...)
	if recipientAnyone {
		sig = append(sig, 0)
	} else {
		sig = append(sig, verifier.Compressed()...)
	}
	sig = append(sig, keyID...)
	signatureDER, err := signature.ToDER()
	if err != nil {
		return nil, err
	}
	sig = append(sig, signatureDER...)
	return sig, nil
}

func Verify(message []byte, sig []byte, recipient *ec.PrivateKey) (bool, error) {
	counter := 4
	// 检查签名长度是否足够
	if len(sig) < counter {
		return false, fmt.Errorf("signature too short: expected at least %d bytes, got %d", counter, len(sig))
	}

	messageVersion := sig[:counter]
	if !bytes.Equal(messageVersion, VERSION_BYTES) {
		return false, fmt.Errorf("message version mismatch: Expected %x, received %x", VERSION_BYTES, messageVersion)
	}

	// 检查签名长度是否足够提取公钥
	if len(sig) < counter+33 {
		return false, fmt.Errorf("signature too short for pubkey: expected at least %d bytes, got %d", counter+33, len(sig))
	}

	pubKeyBytes := sig[counter : counter+33]
	counter += 33

	signer, err := ec.ParsePubKey(pubKeyBytes)
	if err != nil {
		return false, err
	}

	// 检查签名长度是否足够提取verifierFirst
	if len(sig) <= counter {
		return false, fmt.Errorf("signature too short for verifierFirst: expected at least %d bytes, got %d", counter+1, len(sig))
	}

	verifierFirst := sig[counter]

	if verifierFirst == 0 {
		// 根据BRC-77协议，当Verifier ID为0x00时，表示"任何人可验证"模式
		// 使用32字节大端序整数值1作为特殊私钥，与TypeScript端保持一致
		specialKey := make([]byte, 32)
		specialKey[31] = 1 // 大端序表示的整数1
		recipient, _ = ec.PrivateKeyFromBytes(specialKey)
		counter++
	} else {
		counter++

		// 检查签名长度是否足够提取verifierRest
		if len(sig) < counter+32 {
			return false, fmt.Errorf("signature too short for verifierRest: expected at least %d bytes, got %d", counter+32, len(sig))
		}

		verifierRest := sig[counter : counter+32]
		counter += 32
		verifierDER := append([]byte{verifierFirst}, verifierRest...)

		if recipient == nil {
			return false, nil
		}

		recipientDER := recipient.PubKey().Compressed()
		if !bytes.Equal(verifierDER, recipientDER) {
			errorStr := "the recipient public key is %x but the signature requres the recipient to have public key %x"
			err = fmt.Errorf(errorStr, recipientDER, verifierDER)
			return false, err
		}
	}

	// 检查签名长度是否足够提取keyID
	if len(sig) < counter+32 {
		return false, fmt.Errorf("signature too short for keyID: expected at least %d bytes, got %d", counter+32, len(sig))
	}

	keyID := sig[counter : counter+32]
	counter += 32

	// 检查签名长度是否足够提取signatureDER
	if len(sig) <= counter {
		return false, fmt.Errorf("signature too short for signatureDER: expected more than %d bytes, got %d", counter, len(sig))
	}

	signatureDER := sig[counter:]
	signature, err := ec.FromDER(signatureDER)
	if err != nil {
		return false, err
	}

	keyIDBase64 := base64.StdEncoding.EncodeToString(keyID)
	invoiceNumber := "2-message signing-" + keyIDBase64

	// 使用DeriveChild方法，与TypeScript端保持一致
	// 在TypeScript中，派生密钥是通过signer.deriveChild(verifier, invoiceNumber)完成的
	// 在Go中，我们需要使用公钥的DeriveChild方法
	signingKey, err := signer.DeriveChild(recipient, invoiceNumber)
	if err != nil {
		return false, err
	}

	// 直接使用原始消息进行验证
	// 注意：PublicKey.Verify方法已经在内部对消息进行了SHA256哈希处理
	// 这与TypeScript端的实现一致，其中也在verify方法内部进行了哈希处理
	verified := signingKey.Verify(message, signature)

	return verified, nil
}
