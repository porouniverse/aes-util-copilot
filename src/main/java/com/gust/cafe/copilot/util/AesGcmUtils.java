package com.gust.cafe.copilot.util;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * AES-GCM 加解密工具（路线 B）
 *
 * <p>安全分析文档（20260924_155504）附录 D.10 确定：
 * <pre>
 * 密文 = Hex( Salt(16B) || IV(12B) || Ciphertext+Tag(16B) )
 *              └随机      └随机(GCM推荐12B)  └ GCM 自动附加 tag
 * </pre>
 *
 * <p>密钥派生：PBKDF2WithHmacSHA256(password, salt, 65536, 256)
 * <p>加密模式：AES/GCM/NoPadding（带 128-bit 认证标签）
 * <p>每次加解密都走 PBKDF2 重派生密钥，不做缓存。
 *
 * <p>安全边界：
 * <ul>
 *   <li>防文件失窃：密文 Salt/IV/Tag 全部公开也安全，依赖密码强度</li>
 *   <li>防密文篡改：GCM Tag 校验失败抛 {@code AEADBadTagException}</li>
 *   <li>不防内存转储 / 木马：内存中出现的明文和密钥无法规避</li>
 * </ul>
 *
 * @author Dororo (v3.0 upgrade)
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc5116">RFC 5116 - AES-GCM</a>
 */
public class AesGcmUtils {

    // === 布局常量 ===
    /** Salt 长度 16 字节（随机生成，随密文存储） */
    private static final int SALT_LEN = 16;
    /** IV 长度 12 字节（GCM 推荐值，随机生成，随密文存储） */
    private static final int IV_LEN = 12;
    /** GCM 认证标签长度 128 bit = 16 字节（GCM 自动附加） */
    private static final int TAG_LEN_BITS = 128;

    // === KDF 常量 ===
    /** PBKDF2 迭代次数（沿用原版 65536） */
    private static final int PBKDF2_ITERATIONS = 65536;
    /** 派生密钥长度 256 bit = AES-256 */
    private static final int KEY_LEN_BITS = 256;

    // === 算法名称 ===
    private static final String KDF_ALGO = "PBKDF2WithHmacSHA256";
    private static final String CIPHER_ALGO = "AES";
    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";

    private AesGcmUtils() {
        // 工具类禁止实例化
    }

    /**
     * 加密
     *
     * @param password  用户密码（密钥来源）
     * @param plaintext 待加密明文
     * @return Hex 编码的密文：Salt(16B) || IV(12B) || Ciphertext+Tag
     * @throws IllegalArgumentException password 或 plaintext 为 null
     * @throws RuntimeException         加密过程中的密码学异常
     */
    public static String encryptHex(String password, String plaintext) {
        if (password == null) {
            throw new IllegalArgumentException("password must not be null");
        }
        if (plaintext == null) {
            throw new IllegalArgumentException("plaintext must not be null");
        }

        try {
            // 1. 生成随机 Salt 和 IV
            byte[] salt = generateRandomBytes(SALT_LEN);
            byte[] iv = generateRandomBytes(IV_LEN);

            // 2. PBKDF2 派生 AES-256 密钥
            SecretKeySpec key = deriveKey(password, salt);

            // 3. AES-GCM 加密
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LEN_BITS, iv));
            byte[] ciphertextPlusTag = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            // 4. 拼接 Salt || IV || Ciphertext+Tag → Hex 输出
            byte[] output = new byte[SALT_LEN + IV_LEN + ciphertextPlusTag.length];
            System.arraycopy(salt, 0, output, 0, SALT_LEN);
            System.arraycopy(iv, 0, output, SALT_LEN, IV_LEN);
            System.arraycopy(ciphertextPlusTag, 0, output, SALT_LEN + IV_LEN, ciphertextPlusTag.length);

            return bytesToHex(output);
        } catch (Exception e) {
            throw new RuntimeException("AES-GCM encryption failed", e);
        }
    }

    /**
     * 解密
     *
     * @param password     用户密码（密钥来源）
     * @param hexCiphertext encryptHex 的输出
     * @return 恢复的明文
     * @throws IllegalArgumentException  hex 格式错误或长度不足
     * @throws javax.crypto.AEADBadTagException GCM 认证标签校验失败
     *                                  （密码错误 或 密文被篡改都会抛这个，无法区分）
     */
    public static String decryptStr(String password, String hexCiphertext) throws AEADBadTagException {
        if (password == null) {
            throw new IllegalArgumentException("password must not be null");
        }
        if (hexCiphertext == null) {
            throw new IllegalArgumentException("hexCiphertext must not be null");
        }

        byte[] input;
        try {
            input = hexToBytes(hexCiphertext);
        } catch (Exception e) {
            throw new IllegalArgumentException("invalid hex string", e);
        }

        // 最小长度 = Salt(16) + IV(12) + Tag(16) = 44 字节
        if (input.length < SALT_LEN + IV_LEN + TAG_LEN_BITS / 8) {
            throw new IllegalArgumentException("ciphertext too short, minimum 44 bytes (88 hex chars)");
        }

        try {
            // 1. 切分 Salt / IV / Ciphertext+Tag
            byte[] salt = Arrays.copyOfRange(input, 0, SALT_LEN);
            byte[] iv = Arrays.copyOfRange(input, SALT_LEN, SALT_LEN + IV_LEN);
            byte[] ciphertextPlusTag = Arrays.copyOfRange(input, SALT_LEN + IV_LEN, input.length);

            // 2. 用密码 + 密文中携带的 Salt 重派生密钥
            SecretKeySpec key = deriveKey(password, salt);

            // 3. AES-GCM 解密（Tag 校验在 doFinal 内部自动完成）
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LEN_BITS, iv));
            byte[] plaintextBytes = cipher.doFinal(ciphertextPlusTag);

            return new String(plaintextBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            // GCM tag 校验失败会抛 AEADBadTagException
            // 密码错误 vs 密文篡改 在 GCM 语义下无法区分，这是设计预期
            if (e instanceof AEADBadTagException) {
                throw (AEADBadTagException) e;
            }
            throw new RuntimeException("AES-GCM decryption failed", e);
        }
    }

    // ==================== 私有辅助方法 ====================

    /**
     * PBKDF2 密钥派生：password + salt → 256 bit AES 密钥
     */
    private static SecretKeySpec deriveKey(String password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF_ALGO);
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_LEN_BITS);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), CIPHER_ALGO);
    }

    /**
     * 密码学安全的随机字节生成
     */
    private static byte[] generateRandomBytes(int len) throws Exception {
        byte[] buf = new byte[len];
        SecureRandom.getInstanceStrong().nextBytes(buf);
        return buf;
    }

    // ==================== Hex 编解码（自包含，无外部依赖） ====================

    private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();

    /** byte[] → 小写 hex 字符串（package-private，供测试复用） */
    static String bytesToHex(byte[] bytes) {
        char[] hex = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hex[i * 2] = HEX_CHARS[v >>> 4];
            hex[i * 2 + 1] = HEX_CHARS[v & 0x0F];
        }
        return new String(hex);
    }

    /** hex 字符串（大小写均可）→ byte[]（package-private，供测试复用） */
    static byte[] hexToBytes(String hex) {
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("hex string must have even length");
        }
        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < result.length; i++) {
            int hi = Character.digit(hex.charAt(i * 2), 16);
            int lo = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("invalid hex character at position " + i);
            }
            result[i] = (byte) ((hi << 4) | lo);
        }
        return result;
    }
}
