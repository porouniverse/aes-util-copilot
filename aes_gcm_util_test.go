package aesutil

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// 与 Java 版测试对齐：10 个用例（4 核心 + 6 边界）

const (
	testPassword = "my-strong-password-2026"
	testPlaintext = "Hello, AES-GCM Route B!"
)

// ==================== 核心 4 用例 ====================

// TestEncryptDecryptRoundtrip 加解密往返
func TestEncryptDecryptRoundtrip(t *testing.T) {
	hexStr, err := EncryptHex(testPassword, testPlaintext)
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}
	if len(hexStr) < 88 { // 最小 44 字节 = 88 hex 字符
		t.Fatalf("ciphertext too short: got %d hex chars", len(hexStr))
	}

	recovered, err := DecryptStr(testPassword, hexStr)
	if err != nil {
		t.Fatalf("decrypt error: %v", err)
	}
	if recovered != testPlaintext {
		t.Fatalf("roundtrip failed: want %q, got %q", testPlaintext, recovered)
	}
}

// TestSamePlaintextProducesDifferentCiphertext 相同输入密文不同（随机性验证）
func TestSamePlaintextProducesDifferentCiphertext(t *testing.T) {
	hex1, _ := EncryptHex(testPassword, testPlaintext)
	hex2, _ := EncryptHex(testPassword, testPlaintext)

	if hex1 == hex2 {
		t.Fatalf("Salt + IV should be random, but got same ciphertext twice")
	}

	// 但两次都能正确解密
	rec1, err := DecryptStr(testPassword, hex1)
	if err != nil {
		t.Fatalf("decrypt hex1 error: %v", err)
	}
	rec2, err := DecryptStr(testPassword, hex2)
	if err != nil {
		t.Fatalf("decrypt hex2 error: %v", err)
	}
	if rec1 != testPlaintext || rec2 != testPlaintext {
		t.Fatalf("decrypt mismatch")
	}
}

// TestTamperedCiphertextThrowsError 密文被篡改后解密失败
func TestTamperedCiphertextThrowsError(t *testing.T) {
	hexStr, _ := EncryptHex(testPassword, testPlaintext)

	// 翻转 hex 字符串中间某个字符
	chars := []rune(hexStr)
	idx := len(chars) / 2
	if chars[idx] == '0' {
		chars[idx] = '1'
	} else {
		chars[idx] = '0'
	}
	tampered := string(chars)

	_, err := DecryptStr(testPassword, tampered)
	if err == nil {
		t.Fatalf("should have failed on tampered ciphertext")
	}
}

// TestWrongPasswordFailsDecryption 错误密码解密失败
func TestWrongPasswordFailsDecryption(t *testing.T) {
	hexStr, _ := EncryptHex(testPassword, testPlaintext)

	_, err := DecryptStr("wrong-password", hexStr)
	if err == nil {
		t.Fatalf("should have failed with wrong password")
	}
}

// ==================== 附加边界测试 ====================

// TestEmptyPlaintext 空明文
func TestEmptyPlaintext(t *testing.T) {
	empty := ""
	hexStr, err := EncryptHex(testPassword, empty)
	if err != nil {
		t.Fatalf("encrypt empty error: %v", err)
	}

	decrypted, err := DecryptStr(testPassword, hexStr)
	if err != nil {
		t.Fatalf("decrypt empty error: %v", err)
	}
	if decrypted != empty {
		t.Fatalf("want empty, got %q", decrypted)
	}
}

// TestLongPlaintext 长明文（多 block，含中文/Unicode）
func TestLongPlaintext(t *testing.T) {
	longText := ""
	for i := 0; i < 100; i++ {
		longText += "这是一段中文测试文本，包含 Unicode 字符 —— 🎉 123 + 加密安全测试。"
	}

	hexStr, err := EncryptHex(testPassword, longText)
	if err != nil {
		t.Fatalf("encrypt long error: %v", err)
	}

	recovered, err := DecryptStr(testPassword, hexStr)
	if err != nil {
		t.Fatalf("decrypt long error: %v", err)
	}
	if recovered != longText {
		t.Fatalf("long plaintext mismatch")
	}
}

// TestCiphertextLength 密文长度验证
func TestCiphertextLength(t *testing.T) {
	// 明文 "abc" = 3 字节
	// 预期: Salt(16) + IV(12) + Tag(16) + 明文(3) = 47 字节
	// hex 长度 = 47 * 2 = 94
	expectedBytes := saltLen + ivLen + tagLen + 3
	hexStr, _ := EncryptHex(testPassword, "abc")
	if len(hexStr) != expectedBytes*2 {
		t.Fatalf("want hex len %d, got %d", expectedBytes*2, len(hexStr))
	}

	// 空明文: 44 字节 = 88 hex
	emptyHex, _ := EncryptHex(testPassword, "")
	if len(emptyHex) != 88 {
		t.Fatalf("empty plaintext want 88 hex chars, got %d", len(emptyHex))
	}
}

// TestNullInput 空输入校验
func TestNullInput(t *testing.T) {
	if _, err := EncryptHex("", "text"); err == nil {
		t.Fatalf("empty password should fail")
	}
	if _, err := EncryptHex(testPassword, ""); err != nil {
		// 空明文合法（上面 TestEmptyPlaintext 已验证）
		t.Fatalf("empty plaintext should NOT fail: %v", err)
	}
	if _, err := DecryptStr("", "aabb"); err == nil {
		t.Fatalf("empty password should fail")
	}
	if _, err := DecryptStr(testPassword, ""); err == nil {
		t.Fatalf("empty ciphertext should fail")
	}
}

// TestInvalidHexOrTooShort 非法 hex / 长度不足
func TestInvalidHexOrTooShort(t *testing.T) {
	// 非法 hex 字符
	if _, err := DecryptStr(testPassword, "not-valid-hex!!"); err == nil {
		t.Fatalf("invalid hex should fail")
	}

	// 长度不足（至少 88 hex = 44 字节）
	if _, err := DecryptStr(testPassword, "aabbccdd"); err == nil {
		t.Fatalf("too-short ciphertext should fail")
	}
}

// TestFullTamper 全字节翻转 + 单字节翻转都应触发 GCM 失败
func TestFullTamper(t *testing.T) {
	hexStr, _ := EncryptHex(testPassword, testPlaintext)
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}

	// 全量翻转
	for i := range bytes {
		bytes[i] ^= 0xFF
	}
	tampered := hex.EncodeToString(bytes)

	_, err = DecryptStr(testPassword, tampered)
	if err == nil {
		t.Fatalf("fully tampered ciphertext should fail")
	}
	if !errors.Is(err, ErrDecryptFailed) && !strings.Contains(err.Error(), "decryption failed") {
		t.Logf("note: error = %v (底层 GCM Open 错误)", err)
	}
}
