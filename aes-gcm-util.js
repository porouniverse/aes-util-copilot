/**
 * AES-GCM 加解密工具（路线 B）- Node.js 版
 *
 * 安全分析文档（20260924_155504）附录 D.10 确定：
 *   密文 = Hex( Salt(16B) || IV(12B) || Ciphertext || Tag(16B) )
 *                └随机      └随机(GCM推荐12B)  └ GCM 自动附加 tag（Node 需手动拼接）
 *
 * 密钥派生：PBKDF2-SHA256(password, salt, 65536, 256)
 * 加密模式：aes-256-gcm（带 128-bit 认证标签）
 * 每次加解密都走 PBKDF2 重派生密钥，不做缓存。
 *
 * 零 npm 依赖 — 全部使用 Node.js 原生 crypto 模块。
 *
 * 与 Java / Go 版对齐约定：
 *   Salt 16B / IV 12B / Tag 16B / PBKDF2-SHA256-65536-256 / 小写 hex
 */

const crypto = require('node:crypto');

// ==================== 布局常量 ====================
const SALT_LEN = 16;   // 盐长度
const IV_LEN = 12;     // IV 长度（GCM 推荐值）
const TAG_LEN = 16;    // Tag 长度 128 bit = 16 字节（aes-256-gcm 默认就是 128 bit）
const KEY_LEN = 32;    // 派生密钥长度 256 bit = AES-256
const PBKDF2_ITERATIONS = 65536;
const CIPHER_ALGO = 'aes-256-gcm';
const KDF_ALGO = 'sha256';

/**
 * 加密：password + plaintext → hex(Salt || IV || Ciphertext || Tag)
 *
 * @param {string} password  用户密码
 * @param {string} plaintext 待加密明文
 * @returns {string} Hex 编码的密文
 * @throws {Error} password 为空 或 加密过程异常
 */
function encryptHex(password, plaintext) {
    if (!password) throw new Error('password must not be empty');

    // 1. 生成随机 Salt 和 IV
    const salt = crypto.randomBytes(SALT_LEN);
    const iv = crypto.randomBytes(IV_LEN);

    // 2. PBKDF2 派生 AES-256 密钥（同步）
    const key = crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, KEY_LEN, KDF_ALGO);

    // 3. AES-GCM 加密
    const cipher = crypto.createCipheriv(CIPHER_ALGO, key, iv);
    const ciphertext = Buffer.concat([
        cipher.update(plaintext, 'utf8'),
        cipher.final(),
    ]);
    // ⚠️ Node GCM 的 tag 需要单独取（不同于 Java/Go 的 doFinal/Seal 自动拼接）
    const tag = cipher.getAuthTag();

    // 4. 拼接 Salt || IV || Ciphertext || Tag → 小写 hex
    const output = Buffer.concat([salt, iv, ciphertext, tag]);
    return output.toString('hex').toLowerCase();
}

/**
 * 解密：password + hexCiphertext → plaintext
 *
 * GCM 语义说明：
 *   - 密码错误 或 密文被篡改 都会抛出 Error（无法区分，这是 GCM 设计预期）
 *   - 密文格式错误（hex 非法 / 长度不足）会返回具体的格式错误
 *
 * @param {string} password      用户密码
 * @param {string} hexCiphertext encryptHex 的输出
 * @returns {string} 恢复的明文
 * @throws {Error} 解密失败
 */
function decryptStr(password, hexCiphertext) {
    if (!password) throw new Error('password must not be empty');
    if (!hexCiphertext) throw new Error('hexCiphertext must not be empty');

    // 1. Hex 解码（Buffer.from 对非法字符静默跳过，需先严格校验）
    if (!/^[0-9a-fA-F]+$/.test(hexCiphertext)) {
        throw new Error('invalid hex string: contains non-hex characters');
    }
    if (hexCiphertext.length % 2 !== 0) {
        throw new Error('invalid hex string: odd length');
    }
    let input;
    try {
        input = Buffer.from(hexCiphertext, 'hex');
    } catch (e) {
        throw new Error(`invalid hex string: ${e.message}`);
    }

    // 最小长度 = Salt(16) + IV(12) + Tag(16) = 44 字节
    const MIN_LEN = SALT_LEN + IV_LEN + TAG_LEN;
    if (input.length < MIN_LEN) {
        throw new Error(`ciphertext too short, minimum ${MIN_LEN} bytes (${MIN_LEN * 2} hex chars)`);
    }

    // 2. 切分 Salt / IV / Ciphertext / Tag
    //    [0..16) Salt | [16..28) IV | [28..end-16) Ciphertext | [end-16..end) Tag
    const salt = input.subarray(0, SALT_LEN);
    const iv = input.subarray(SALT_LEN, SALT_LEN + IV_LEN);
    const ciphertext = input.subarray(SALT_LEN + IV_LEN, input.length - TAG_LEN);
    const tag = input.subarray(input.length - TAG_LEN, input.length);

    // 3. 用密码 + 密文中携带的 Salt 重派生密钥
    const key = crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, KEY_LEN, KDF_ALGO);

    // 4. AES-GCM 解密（Tag 校验在 decipher.final() 时触发）
    const decipher = crypto.createDecipheriv(CIPHER_ALGO, key, iv);
    decipher.setAuthTag(tag); // 必须在 update/final 之前设置

    let plaintextBuf;
    try {
        plaintextBuf = Buffer.concat([
            decipher.update(ciphertext),
            decipher.final(),
        ]);
    } catch (e) {
        // 密码错误 vs 密文篡改 在 GCM 语义下无法区分
        // Node 底层抛出的是 Error: Unsupported state or unable to authenticate data
        throw new Error(`decryption failed (wrong password or tampered ciphertext): ${e.message}`);
    }

    return plaintextBuf.toString('utf8');
}

module.exports = {
    encryptHex,
    decryptStr,
    // 常量导出供测试对齐
    CONSTANTS: {
        SALT_LEN, IV_LEN, TAG_LEN, KEY_LEN, PBKDF2_ITERATIONS,
    },
};
