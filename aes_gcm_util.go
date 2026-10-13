package aesutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

/*
	AES-GCM 加解密工具（路线 B）

	安全分析文档（20260924_155504）附录 D.10 确定：
		密文 = Hex( Salt(16B) || IV(12B) || Ciphertext+Tag(16B) )
					 └随机      └随机(GCM推荐12B)  └ GCM 自动附加 tag

	密钥派生：PBKDF2WithHmacSHA256(password, salt, 65536, 256)
	加密模式：AES-GCM（带 128-bit 认证标签）
	每次加解密都走 PBKDF2 重派生密钥，不做缓存。

	安全边界：
	- 防文件失窃：密文 Salt/IV/Tag 全部公开也安全，依赖密码强度
	- 防密文篡改：GCM Open 失败返回 ErrOpen
	- 不防内存转储 / 木马

	与 Java 版对齐：Salt 16B / IV 12B / Tag 16B / PBKDF2-SHA256-65536-256
*/

const (
	saltLen   = 16 // 盐长度
	ivLen     = 12 // IV 长度（GCM 推荐值）
	tagLen    = 16 // Tag 长度 128 bit = 16 字节
	keyLen    = 32 // 派生密钥长度 256 bit = AES-256
	pbkdf2Itr = 65536
)

// ErrDecryptFailed 解密失败（密码错误 或 密文被篡改，GCM 语义下无法区分）
// 底层对应 cipher.AEAD 的 Open 返回 err
var ErrDecryptFailed = errors.New("aes-gcm: decryption failed (wrong password or tampered ciphertext)")

// EncryptHex 加密：password + plaintext → hex(Salt || IV || Ciphertext+Tag)
func EncryptHex(password, plaintext string) (string, error) {
	if password == "" {
		return "", errors.New("password must not be empty")
	}

	// 1. 生成随机 Salt 和 IV
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("salt generation failed: %w", err)
	}
	iv := make([]byte, ivLen)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("iv generation failed: %w", err)
	}

	// 2. PBKDF2 派生 AES-256 密钥（标准库 crypto/pbkdf2，Go 1.24+）
	key, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Itr, keyLen)
	if err != nil {
		return "", fmt.Errorf("pbkdf2 failed: %w", err)
	}

	// 3. AES-GCM 加密
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("cipher creation failed: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm creation failed: %w", err)
	}

	// Seal 返回 ciphertext || tag（IV 不自动前缀，需要自己拼）
	ctPlusTag := gcm.Seal(nil, iv, []byte(plaintext), nil)

	// 4. 拼接 Salt || IV || Ciphertext+Tag → hex 输出
	output := make([]byte, 0, saltLen+ivLen+len(ctPlusTag))
	output = append(output, salt...)
	output = append(output, iv...)
	output = append(output, ctPlusTag...)

	return hex.EncodeToString(output), nil
}

// DecryptStr 解密：password + hexCiphertext → plaintext
//
// GCM 语义说明：
//   - 密码错误 或 密文被篡改 都会返回 ErrDecryptFailed（无法区分）
//   - 密文格式错误（hex 非法 / 长度不足）会返回具体的格式错误
func DecryptStr(password, hexCiphertext string) (string, error) {
	if password == "" {
		return "", errors.New("password must not be empty")
	}

	// 1. Hex 解码
	input, err := hex.DecodeString(hexCiphertext)
	if err != nil {
		return "", fmt.Errorf("invalid hex string: %w", err)
	}

	// 最小长度 = Salt(16) + IV(12) + Tag(16) = 44 字节
	minLen := saltLen + ivLen + tagLen
	if len(input) < minLen {
		return "", fmt.Errorf("ciphertext too short, minimum %d bytes (%d hex chars)", minLen, minLen*2)
	}

	// 2. 切分 Salt / IV / Ciphertext+Tag
	salt := input[:saltLen]
	iv := input[saltLen : saltLen+ivLen]
	ctPlusTag := input[saltLen+ivLen:]

	// 3. 用密码 + 密文中携带的 Salt 重派生密钥
	key, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Itr, keyLen)
	if err != nil {
		return "", fmt.Errorf("pbkdf2 failed: %w", err)
	}

	// 4. AES-GCM 解密（Tag 校验在 Open 内部自动完成）
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("cipher creation failed: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm creation failed: %w", err)
	}

	plaintext, err := gcm.Open(nil, iv, ctPlusTag, nil)
	if err != nil {
		// 密码错误 vs 密文篡改 在 GCM 语义下无法区分，这是设计预期
		// 底层就是 cipher.AEAD 的 Open 返回错误
		return "", fmt.Errorf("%w: %v", ErrDecryptFailed, err)
	}

	return string(plaintext), nil
}
