package com.gust.cafe.copilot.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link AesGcmUtils} 单元测试
 */
@DisplayName("AES-GCM 加解密工具测试")
class AesGcmUtilsTest {

    private static final String PASSWORD = "my-strong-password-2026";
    private static final String PLAINTEXT = "Hello, AES-GCM Route B!";

    // ==================== 核心 4 用例 ====================

    @Test
    @DisplayName("加解密往返：encryptHex → decryptStr 还原原明文")
    void testEncryptDecryptRoundtrip() throws Exception {
        String hex = AesGcmUtils.encryptHex(PASSWORD, PLAINTEXT);
        assertNotNull(hex, "加密结果不应为 null");
        assertTrue(hex.length() >= 88, "密文 hex 最小长度应为 88 (44 字节)");

        String recovered = AesGcmUtils.decryptStr(PASSWORD, hex);
        assertEquals(PLAINTEXT, recovered, "解密应还原原明文");
    }

    @Test
    @DisplayName("随机性：相同密码+明文，连续加密两次产出不同密文")
    void testSamePlaintextProducesDifferentCiphertext() throws Exception {
        String hex1 = AesGcmUtils.encryptHex(PASSWORD, PLAINTEXT);
        String hex2 = AesGcmUtils.encryptHex(PASSWORD, PLAINTEXT);

        assertNotEquals(hex1, hex2, "Salt + IV 每次随机，密文应不同");

        // 但两次都能正确解密还原
        assertEquals(PLAINTEXT, AesGcmUtils.decryptStr(PASSWORD, hex1));
        assertEquals(PLAINTEXT, AesGcmUtils.decryptStr(PASSWORD, hex2));
    }

    @Test
    @DisplayName("防篡改：密文翻转一字节后解密抛 AEADBadTagException")
    void testTamperedCiphertextThrowsAEADBadTagException() {
        String hex = AesGcmUtils.encryptHex(PASSWORD, PLAINTEXT);

        // 翻转 hex 字符串中间某个字符（对应密文中某个字节）
        char[] hexChars = hex.toCharArray();
        int tamperIdx = hexChars.length / 2;
        hexChars[tamperIdx] = (hexChars[tamperIdx] == '0') ? '1' : '0';
        String tampered = new String(hexChars);

        assertThrows(AEADBadTagException.class,
                () -> AesGcmUtils.decryptStr(PASSWORD, tampered),
                "密文被篡改后应抛 AEADBadTagException");
    }

    @Test
    @DisplayName("错密码：用错误密码解正确密文抛 AEADBadTagException")
    void testWrongPasswordFailsDecryption() {
        String hex = AesGcmUtils.encryptHex(PASSWORD, PLAINTEXT);

        assertThrows(AEADBadTagException.class,
                () -> AesGcmUtils.decryptStr("wrong-password", hex),
                "错误密码应导致 GCM tag 校验失败");
    }

    // ==================== 附加边界测试 ====================

    @Nested
    @DisplayName("边界场景")
    class EdgeCases {

        @Test
        @DisplayName("空明文也能正常加解密")
        void testEmptyPlaintext() throws Exception {
            String empty = "";
            String hex = AesGcmUtils.encryptHex(PASSWORD, empty);
            assertEquals(empty, AesGcmUtils.decryptStr(PASSWORD, hex));
        }

        @Test
        @DisplayName("长明文（多 block）正常加解密")
        void testLongPlaintext() throws Exception {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 100; i++) {
                sb.append("这是一段中文测试文本，包含 Unicode 字符 —— 🎉 123 + 加密安全测试。");
            }
            String longText = sb.toString();

            String hex = AesGcmUtils.encryptHex(PASSWORD, longText);
            String recovered = AesGcmUtils.decryptStr(PASSWORD, hex);

            assertEquals(longText, recovered, "长明文应完整还原");
        }

        @Test
        @DisplayName("密文长度验证：Salt16 + IV12 + Tag16 + 明文N = 44+N 字节")
        void testCiphertextLength() {
            byte[] plaintextBytes = "abc".getBytes();
            int expectedBytes = 16 + 12 + plaintextBytes.length + 16; // Salt + IV + CT + Tag

            String hex = AesGcmUtils.encryptHex(PASSWORD, "abc");
            assertEquals(expectedBytes * 2, hex.length(),
                    "hex 长度应为 " + expectedBytes + " 字节 × 2");

            // 空明文验证最小长度
            String emptyHex = AesGcmUtils.encryptHex(PASSWORD, "");
            assertEquals(88, emptyHex.length(), "空明文 hex 应为 88 字符 (44 字节)");
        }

        @Test
        @DisplayName("输入 null 抛 IllegalArgumentException")
        void testNullInput() {
            assertThrows(IllegalArgumentException.class,
                    () -> AesGcmUtils.encryptHex(null, "text"));
            assertThrows(IllegalArgumentException.class,
                    () -> AesGcmUtils.encryptHex(PASSWORD, null));
            assertThrows(IllegalArgumentException.class,
                    () -> AesGcmUtils.decryptStr(null, "hex"));
            assertThrows(IllegalArgumentException.class,
                    () -> AesGcmUtils.decryptStr(PASSWORD, null));
        }

        @Test
        @DisplayName("非法 hex / 长度不足 抛 IllegalArgumentException")
        void testInvalidHexOrTooShort() {
            assertThrows(IllegalArgumentException.class,
                    () -> AesGcmUtils.decryptStr(PASSWORD, "not-valid-hex!!"));
            // 长度：至少 88 个 hex 字符（44 字节）
            assertThrows(IllegalArgumentException.class,
                    () -> AesGcmUtils.decryptStr(PASSWORD, "aabbccdd"));
        }

        @Test
        @DisplayName("全字节翻转 vs 单字节翻转：tag 校验均失败")
        void testFullTamper() {
            String hex = AesGcmUtils.encryptHex(PASSWORD, PLAINTEXT);
            byte[] bytes = AesGcmUtils.hexToBytes(hex);

            // 全量翻转
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] ^= 0xFF;
            }

            assertThrows(AEADBadTagException.class,
                    () -> AesGcmUtils.decryptStr(PASSWORD, AesGcmUtils.bytesToHex(bytes)));
        }
    }
}
