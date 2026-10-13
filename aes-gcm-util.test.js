/**
 * AES-GCM 工具类测试（与 Java / Go 版 10 用例对齐）
 * 运行: node --test aes-gcm-util.test.js
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { encryptHex, decryptStr } = require('./aes-gcm-util.js');

const PASSWORD = 'my-strong-password-2026';
const PLAINTEXT = 'Hello, AES-GCM Route B!';

// ==================== 核心 4 用例 ====================

describe('核心测试', () => {

    it('加解密往返：encryptHex → decryptStr 还原原明文', () => {
        const hex = encryptHex(PASSWORD, PLAINTEXT);
        assert.ok(hex.length >= 88, `密文 hex 最小 88 字符，实际 ${hex.length}`);

        const recovered = decryptStr(PASSWORD, hex);
        assert.equal(recovered, PLAINTEXT, '解密应还原原明文');
    });

    it('随机性：相同密码+明文，连续加密两次产出不同密文', () => {
        const hex1 = encryptHex(PASSWORD, PLAINTEXT);
        const hex2 = encryptHex(PASSWORD, PLAINTEXT);

        assert.notEqual(hex1, hex2, 'Salt + IV 每次随机，密文应不同');

        assert.equal(decryptStr(PASSWORD, hex1), PLAINTEXT);
        assert.equal(decryptStr(PASSWORD, hex2), PLAINTEXT);
    });

    it('防篡改：密文翻转一字节后解密抛错', () => {
        const hex = encryptHex(PASSWORD, PLAINTEXT);
        const chars = hex.split('');
        const idx = Math.floor(chars.length / 2);
        chars[idx] = chars[idx] === '0' ? '1' : '0';
        const tampered = chars.join('');

        assert.throws(
            () => decryptStr(PASSWORD, tampered),
            /decryption failed|Unsupported state|unable to authenticate/,
            '密文被篡改后应抛解密失败'
        );
    });

    it('错密码：用错误密码解正确密文抛错', () => {
        const hex = encryptHex(PASSWORD, PLAINTEXT);

        assert.throws(
            () => decryptStr('wrong-password', hex),
            /decryption failed|Unsupported state|unable to authenticate/,
            '错误密码应导致 GCM tag 校验失败'
        );
    });
});

// ==================== 附加边界测试 ====================

describe('边界场景', () => {

    it('空明文也能正常加解密', () => {
        const empty = '';
        const hex = encryptHex(PASSWORD, empty);
        assert.equal(decryptStr(PASSWORD, hex), empty);
    });

    it('长明文（多 block，中文+Unicode）正常加解密', () => {
        let longText = '';
        for (let i = 0; i < 100; i++) {
            longText += '这是一段中文测试文本，包含 Unicode 字符 —— 🎉 123 + 加密安全测试。';
        }
        const hex = encryptHex(PASSWORD, longText);
        assert.equal(decryptStr(PASSWORD, hex), longText);
    });

    it('密文长度验证：Salt16 + IV12 + Tag16 + 明文N = 44+N 字节', () => {
        // 明文 "abc"=3B → 44+3=47 字节 → 94 hex
        const hex = encryptHex(PASSWORD, 'abc');
        assert.equal(hex.length, 94, `"abc" 应产出 94 hex 字符，实际 ${hex.length}`);

        // 空明文 → 44 字节 → 88 hex
        const emptyHex = encryptHex(PASSWORD, '');
        assert.equal(emptyHex.length, 88, `空明文应产出 88 hex 字符，实际 ${emptyHex.length}`);
    });

    it('空 password / 空 hexCiphertext 抛 Error', () => {
        assert.throws(() => encryptHex('', 'text'), /password must not be empty/);
        assert.throws(() => decryptStr('', 'aabbccdd'), /password must not be empty/);
        assert.throws(() => decryptStr(PASSWORD, ''), /hexCiphertext must not be empty/);
    });

    it('非法 hex / 长度不足 抛 Error', () => {
        // "not-valid-hex!!" 含非 hex 字符
        assert.throws(() => decryptStr(PASSWORD, 'not-valid-hex!!'), /invalid hex/);
        // 合法 hex 但长度不足
        assert.throws(() => decryptStr(PASSWORD, 'aabbccdd'), /too short/);
    });

    it('全字节翻转：tag 校验失败', () => {
        const hex = encryptHex(PASSWORD, PLAINTEXT);
        const buf = Buffer.from(hex, 'hex');
        for (let i = 0; i < buf.length; i++) {
            buf[i] = buf[i] ^ 0xFF;
        }
        const flipped = buf.toString('hex');

        assert.throws(
            () => decryptStr(PASSWORD, flipped),
            /decryption failed|Unsupported state|unable to authenticate/,
            '全字节翻转应触发 GCM 校验失败'
        );
    });
});
