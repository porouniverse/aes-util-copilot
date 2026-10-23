#!/usr/bin/env node
'use strict';
/**
 * AES-GCM 三语言联合测试（Go / Java / Node.js）
 *
 * 流程：
 *   1. 生成 N 组随机密码+明文（种子可复现）            -> out/cases.tsv
 *   2. 三个语言各自加密全部用例（并行）                 -> out/ct_{go,js,java}.tsv
 *   3. 三个语言各自解密全部 3 份密文并逐字节比对（并行） -> out/verify_{go,js,java}.tsv
 *   4. 汇总为逐用例明细 CSV + 成功率/失败率统计
 *
 * 用法：
 *   node run.js                          # 默认 100000 例
 *   node run.js --total 200 --dir out-smoke
 *   node run.js --total 100000 --seed 20261023 --workers-go 2 --workers-js 4 --workers-java 12
 */
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const crypto = require('crypto');
const { spawn } = require('child_process');

const ROOT = __dirname;
const SIB = path.resolve(ROOT, '..');
const JAVA_SRC_ROOT = path.join(SIB, 'aes-util-copilot@java', 'src', 'main', 'java');

const SOURCE_ORDER = ['go', 'js', 'java'];

function main() {
    const opts = parseArgs(process.argv.slice(2));
    const total = parseInt(opts.total || '100000', 10);
    const seed = parseInt(opts.seed || '20261023', 10);
    const outDir = path.resolve(ROOT, opts.dir || 'out');
    const workers = {
        go: parseInt(opts['workers-go'] || '2', 10),
        js: parseInt(opts['workers-js'] || '4', 10),
        java: parseInt(opts['workers-java'] || '12', 10),
    };

    fs.mkdirSync(outDir, { recursive: true });
    const p = (f) => path.join(outDir, f);
    const startedAt = Date.now();

    console.log(`== AES-GCM joint test ==`);
    console.log(`cases=${total} seed=${seed} dir=${outDir}`);
    console.log(`workers: go=${workers.go} js=${workers.js} java=${workers.java} (cpu=${require('os').cpus().length})`);

    const steps = [
        { name: 'build', fn: () => buildAll(outDir) },
        { name: 'generate', fn: () => generateCases(p('cases.tsv'), total, seed) },
        { name: 'encrypt', fn: () => runPhase('encrypt', p, workers) },
        { name: 'verify', fn: () => runPhase('verify', p, workers) },
        { name: 'merge', fn: () => merge(p, outDir, { total, seed, startedAt }) },
    ];
    let chain = Promise.resolve();
    for (const s of steps) {
        if (opts.skip && opts.skip.split(',').includes(s.name)) {
            console.log(`-- skip ${s.name}`);
            continue;
        }
        chain = chain.then(async () => {
            const t = Date.now();
            console.log(`-- ${s.name} ...`);
            await s.fn();
            console.log(`-- ${s.name} done in ${((Date.now() - t) / 1000).toFixed(1)}s`);
        });
    }
    chain.catch((e) => {
        console.error('FAILED:', e.message);
        process.exit(1);
    });
}

// ==================== 构建 ====================

async function buildAll(outDir) {
    const binDir = path.join(outDir, 'bin');
    const classesDir = path.join(outDir, 'java-classes');
    fs.mkdirSync(binDir, { recursive: true });
    fs.mkdirSync(classesDir, { recursive: true });

    await Promise.all([
        runCmd('go-build', 'go', ['build', '-o', path.join(binDir, 'joint-go.exe'), '.'], { cwd: path.join(ROOT, 'go') }),
        runCmd('javac', 'javac', [
            '-encoding', 'UTF-8',
            '-d', classesDir,
            '-sourcepath', JAVA_SRC_ROOT,
            path.join(ROOT, 'java-src', 'JoinTest.java'),
        ]),
    ]);
}

// ==================== 用例生成 ====================

const POOLS = {
    alnum: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'.split(''),
    sym: "!@#$%^&*()-_=+[]{};:'\",.<>/?\\|`~ ".split(''),
    cjk: '中文密码测试数据加密联合验证安全工具密钥盐值随机'.split(''),
    latin: 'àéîõüñáíóúçèìòùâêôûäëïöü'.split(''),
    emoji: ['😀', '🚀', '🔐', '🧪', '✅', '🀄', '𝄞', '🌈', '👨‍👩‍👧'],
    ws: [' ', '\t', '\n'],
};

const PASSWORD_POOLS = [
    { pool: POOLS.alnum, w: 0.60 },
    { pool: POOLS.sym, w: 0.15 },
    { pool: POOLS.cjk, w: 0.15 },
    { pool: POOLS.latin, w: 0.05 },
    { pool: POOLS.emoji, w: 0.05 },
];

const PLAINTEXT_POOLS = [
    { pool: POOLS.alnum, w: 0.50 },
    { pool: POOLS.sym, w: 0.08 },
    { pool: POOLS.cjk, w: 0.15 },
    { pool: POOLS.latin, w: 0.05 },
    { pool: POOLS.emoji, w: 0.04 },
    { pool: POOLS.ws, w: 0.18 },
];

const MAX_PLAINTEXT_BYTES = 4096;

function mulberry32(a) {
    return function () {
        a |= 0;
        a = (a + 0x6D2B79F5) | 0;
        let t = Math.imul(a ^ (a >>> 15), 1 | a);
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}

function intBetween(rng, a, b) {
    return a + Math.floor(rng() * (b - a + 1));
}

function pickPool(rng, pools) {
    const r = rng();
    let acc = 0;
    for (const p of pools) {
        acc += p.w;
        if (r < acc) return p.pool;
    }
    return pools[0].pool;
}

function buildString(rng, len, pools) {
    let s = '';
    for (let i = 0; i < len; i++) {
        const pool = pickPool(rng, pools);
        s += pool[Math.floor(rng() * pool.length)];
    }
    return s;
}

function randomPassword(rng) {
    const r = rng();
    const len = r < 0.05 ? intBetween(rng, 1, 7) : r < 0.75 ? intBetween(rng, 8, 24) : intBetween(rng, 25, 64);
    return buildString(rng, len, PASSWORD_POOLS);
}

function randomPlaintext(rng) {
    const r = rng();
    const chars = r < 0.01 ? 0
        : r < 0.31 ? intBetween(rng, 1, 32)
            : r < 0.81 ? intBetween(rng, 33, 256)
                : r < 0.99 ? intBetween(rng, 257, 1024)
                    : intBetween(rng, 1025, MAX_PLAINTEXT_BYTES);

    let s = '';
    let bytes = 0;
    for (let i = 0; i < chars; i++) {
        const pool = pickPool(rng, PLAINTEXT_POOLS);
        const ch = pool[Math.floor(rng() * pool.length)];
        const b = Buffer.byteLength(ch);
        if (bytes + b > MAX_PLAINTEXT_BYTES) break;
        s += ch;
        bytes += b;
    }
    return s;
}

function generateCases(casesPath, total, seed) {
    const rng = mulberry32(seed);
    const fd = fs.openSync(casesPath, 'w');
    const buf = ['id\tpassword_b64\tplaintext_b64\n'];
    for (let id = 1; id <= total; id++) {
        const pw = randomPassword(rng);
        const pt = randomPlaintext(rng);
        buf.push(`${id}\t${Buffer.from(pw, 'utf8').toString('base64')}\t${Buffer.from(pt, 'utf8').toString('base64')}\n`);
        if (buf.length >= 2000) {
            fs.writeSync(fd, buf.join(''));
            buf.length = 0;
        }
    }
    if (buf.length) fs.writeSync(fd, buf.join(''));
    fs.closeSync(fd);
}

// ==================== 执行三语言 ====================

function commands(phase, p, workers) {
    const cases = p('cases.tsv');
    const ctArgs = [p('ct_go.tsv'), p('ct_js.tsv'), p('ct_java.tsv')].join(',');
    return [
        {
            name: 'go',
            cmd: path.join(p('bin'), 'joint-go.exe'),
            args: phase === 'encrypt'
                ? ['encrypt', '--cases', cases, '--out', p('ct_go.tsv'), '--workers', String(workers.go)]
                : ['verify', '--cases', cases, '--ct', ctArgs, '--out', p('verify_go.tsv'), '--workers', String(workers.go)],
        },
        {
            name: 'js',
            cmd: process.execPath,
            args: phase === 'encrypt'
                ? [path.join(ROOT, 'js', 'cli.js'), 'encrypt', '--cases', cases, '--out', p('ct_js.tsv'), '--workers', String(workers.js)]
                : [path.join(ROOT, 'js', 'cli.js'), 'verify', '--cases', cases, '--ct', ctArgs, '--out', p('verify_js.tsv'), '--workers', String(workers.js)],
        },
        {
            name: 'java',
            cmd: 'java',
            args: phase === 'encrypt'
                ? ['-Xmx2g', '-cp', p('java-classes'), 'JoinTest', 'encrypt', '--cases', cases, '--out', p('ct_java.tsv'), '--workers', String(workers.java)]
                : ['-Xmx2g', '-cp', p('java-classes'), 'JoinTest', 'verify', '--cases', cases, '--ct', ctArgs, '--out', p('verify_java.tsv'), '--workers', String(workers.java)],
        },
    ];
}

function runPhase(phase, p, workers) {
    return Promise.all(commands(phase, p, workers).map((c) => runCmd(c.name, c.cmd, c.args)));
}

// ==================== 汇总 ====================

async function merge(p, outDir, meta) {
    const reportPath = path.join(outDir, 'report.csv');
    const cases = { pwLen: [], pwSha: [], pwPreview: [], ptBytes: [], ptSha: [], ptPreview: [] };
    const ctLen = { go: new Map(), js: new Map(), java: new Map() };
    const ver = { go: new Map(), js: new Map(), java: new Map() };
    let maxId = 0;

    for await (const line of linesFrom(p('cases.tsv'))) {
        if (!line || line.startsWith('id\t')) continue;
        const t1 = line.indexOf('\t');
        const t2 = line.indexOf('\t', t1 + 1);
        const id = parseInt(line.slice(0, t1), 10);
        const pwBuf = Buffer.from(line.slice(t1 + 1, t2), 'base64');
        const ptBuf = Buffer.from(line.slice(t2 + 1), 'base64');
        cases.pwLen[id] = pwBuf.toString('utf8').length;
        cases.pwSha[id] = sha256(pwBuf);
        cases.pwPreview[id] = Buffer.from(pwBuf.toString('utf8').slice(0, 24), 'utf8').toString('base64');
        cases.ptBytes[id] = ptBuf.length;
        cases.ptSha[id] = sha256(ptBuf);
        cases.ptPreview[id] = Buffer.from(ptBuf.toString('utf8').slice(0, 64), 'utf8').toString('base64');
        if (id > maxId) maxId = id;
    }

    for (const lang of SOURCE_ORDER) {
        for await (const line of linesFrom(p(`ct_${lang}.tsv`))) {
            if (!line || line.startsWith('id\t')) continue;
            const f = line.split('\t');
            ctLen[lang].set(parseInt(f[0], 10), (f[1] || '').length);
        }
        for await (const line of linesFrom(p(`verify_${lang}.tsv`))) {
            if (!line || line.startsWith('id\t')) continue;
            const f = line.split('\t');
            ver[lang].set(parseInt(f[0], 10), {
                mask: parseInt(f[1], 10),
                ms: parseFloat(f[2] || '0') + parseFloat(f[3] || '0') + parseFloat(f[4] || '0'),
                err: f[5] && f[5] !== '-' ? Buffer.from(f[5], 'base64').toString('utf8') : '',
            });
        }
    }

    const stats = {
        total: 0, success: 0,
        checks: newCheckStats(),
        encMs: { go: [], js: [], java: [] },
        decMs: { go: [], js: [], java: [] },
        errors: new Map(),
    };

    const fd = fs.openSync(reportPath, 'w');
    let buf = [];
    buf.push([
        'case_id', 'password_len', 'password_sha256', 'password_preview_b64',
        'plaintext_bytes', 'plaintext_sha256', 'plaintext_preview_b64',
        'ct_len_go', 'ct_len_js', 'ct_len_java',
        'self_go', 'go_dec_js', 'go_dec_java',
        'self_js', 'js_dec_go', 'js_dec_java',
        'self_java', 'java_dec_go', 'java_dec_js',
        'checks_passed', 'checks_total', 'all_ok', 'ms_go', 'ms_js', 'ms_java', 'error_b64',
    ].join(',') + '\n');

    for (let id = 1; id <= maxId; id++) {
        const g = ver.go.get(id);
        const j = ver.js.get(id);
        const a = ver.java.get(id);
        const checks = [
            bit(g, 0), bit(g, 1), bit(g, 2),
            bit(j, 1), bit(j, 0), bit(j, 2),
            bit(a, 2), bit(a, 0), bit(a, 1),
        ];
        const passed = checks.filter(Boolean).length;
        const allOk = passed === checks.length;

        stats.total++;
        if (allOk) stats.success++;
        stats.checks.selfGo += checks[0] ? 1 : 0;
        stats.checks.selfJs += checks[3] ? 1 : 0;
        stats.checks.selfJava += checks[6] ? 1 : 0;
        stats.checks.goDecJs += checks[1] ? 1 : 0;
        stats.checks.goDecJava += checks[2] ? 1 : 0;
        stats.checks.jsDecGo += checks[4] ? 1 : 0;
        stats.checks.jsDecJava += checks[5] ? 1 : 0;
        stats.checks.javaDecGo += checks[7] ? 1 : 0;
        stats.checks.javaDecJs += checks[8] ? 1 : 0;

        for (const [lang, v] of [['go', g], ['js', j], ['java', a]]) {
            if (v) stats.decMs[lang].push(v.ms / 3);
            else recordError(stats, lang, 'missing_verify_row');
        }

        const errParts = [];
        if (g && g.err) errParts.push(`go: ${g.err}`);
        if (j && j.err) errParts.push(`js: ${j.err}`);
        if (a && a.err) errParts.push(`java: ${a.err}`);
        for (const e of errParts) {
            const lang = e.slice(0, e.indexOf(':'));
            recordError(stats, lang, classify(e));
        }

        buf.push([
            id,
            cases.pwLen[id] ?? '',
            cases.pwSha[id] ?? '',
            cases.pwPreview[id] ?? '',
            cases.ptBytes[id] ?? '',
            cases.ptSha[id] ?? '',
            cases.ptPreview[id] ?? '',
            ctLen.go.get(id) ?? '',
            ctLen.js.get(id) ?? '',
            ctLen.java.get(id) ?? '',
            ...checks.map((c) => (c ? 1 : 0)),
            passed, checks.length, allOk ? 1 : 0,
            g ? g.ms.toFixed(3) : '',
            j ? j.ms.toFixed(3) : '',
            a ? a.ms.toFixed(3) : '',
            errParts.length ? Buffer.from(errParts.join(' | '), 'utf8').toString('base64') : '-',
        ].join(',') + '\n');

        if (buf.length >= 2000) {
            fs.writeSync(fd, buf.join(''));
            buf = [];
        }
    }
    if (buf.length) fs.writeSync(fd, buf.join(''));
    fs.closeSync(fd);

    // 加密耗时统计（ct 文件第三列）
    for (const lang of SOURCE_ORDER) {
        for await (const line of linesFrom(p(`ct_${lang}.tsv`))) {
            if (!line || line.startsWith('id\t')) continue;
            const f = line.split('\t');
            const ms = parseFloat(f[2]);
            if (!Number.isNaN(ms)) stats.encMs[lang].push(ms);
        }
    }

    const elapsed = (Date.now() - meta.startedAt) / 1000;
    writeSummary(outDir, stats, meta, elapsed);
    console.log(`== summary ==`);
    console.log(`cases=${stats.total} success=${stats.success} rate=${(stats.success / stats.total * 100).toFixed(6)}%`);
    console.log(`detail: ${reportPath}`);
    console.log(`summary: ${path.join(outDir, 'summary.csv')} , ${path.join(outDir, 'summary.md')}`);
}

function newCheckStats() {
    return { selfGo: 0, selfJs: 0, selfJava: 0, goDecJs: 0, goDecJava: 0, jsDecGo: 0, jsDecJava: 0, javaDecGo: 0, javaDecJs: 0 };
}

function bit(v, i) {
    return v ? ((v.mask >> i) & 1) === 1 : false;
}

function recordError(stats, lang, kind) {
    const k = `${lang}:${kind}`;
    stats.errors.set(k, (stats.errors.get(k) || 0) + 1);
}

function classify(msg) {
    if (/missing_verify_row/.test(msg)) return 'missing_verify_row';
    if (/plaintext mismatch/.test(msg)) return 'plaintext_mismatch';
    if (/decryption failed|bad tag|BadTag|unable to authenticate|ErrDecryptFailed/i.test(msg)) return 'auth_failed';
    return 'other';
}

function writeSummary(outDir, stats, meta, elapsed) {
    const total = stats.total;
    const failed = total - stats.success;
    const rate = total ? stats.success / total : 0;
    const checkTotal = total * 9;
    const passedChecks = Object.values(stats.checks).reduce((a, b) => a + b, 0);

    const rows = [];
    const add = (k, v) => rows.push(`${k},${v}`);

    add('total_cases', total);
    add('success_cases', stats.success);
    add('failed_cases', failed);
    add('success_rate', (rate * 100).toFixed(6) + '%');
    add('success_rate_raw', rate.toFixed(9));
    add('failure_rate', ((1 - rate) * 100).toFixed(6) + '%');
    add('failure_rate_raw', (1 - rate).toFixed(9));
    add('total_checks', checkTotal);
    add('passed_checks', passedChecks);
    add('check_pass_rate', ((passedChecks / checkTotal) * 100).toFixed(6) + '%');
    add('decrypt_ops', total * 9);
    add('encrypt_ops', total * 3);
    add('pbkdf2_derivations', total * 12);

    const checkNames = {
        selfGo: 'go_encrypt__go_decrypt',
        selfJs: 'js_encrypt__js_decrypt',
        selfJava: 'java_encrypt__java_decrypt',
        goDecJs: 'js_encrypt__go_decrypt',
        goDecJava: 'java_encrypt__go_decrypt',
        jsDecGo: 'go_encrypt__js_decrypt',
        jsDecJava: 'java_encrypt__js_decrypt',
        javaDecGo: 'go_encrypt__java_decrypt',
        javaDecJs: 'js_encrypt__java_decrypt',
    };
    for (const [key, label] of Object.entries(checkNames)) {
        const ok = stats.checks[key];
        add(`check_rate.${label}`, ((ok / total) * 100).toFixed(6) + '%');
        add(`check_failed.${label}`, total - ok);
    }

    for (const lang of SOURCE_ORDER) {
        add(`avg_encrypt_ms.${lang}`, avg(stats.encMs[lang]).toFixed(3));
        add(`max_encrypt_ms.${lang}`, max(stats.encMs[lang]).toFixed(3));
        add(`avg_decrypt_ms.${lang}`, avg(stats.decMs[lang]).toFixed(3));
        add(`max_decrypt_ms.${lang}`, max(stats.decMs[lang]).toFixed(3));
    }

    add('elapsed_seconds', elapsed.toFixed(1));
    add('cases_per_second', (total / elapsed).toFixed(2));
    add('seed', meta.seed);
    add('generated_at', new Date().toISOString());

    for (const [k, v] of Array.from(stats.errors.entries()).sort()) {
        add(`error_count.${k}`, v);
    }

    fs.writeFileSync(path.join(outDir, 'summary.csv'), rows.join('\n') + '\n', 'utf8');

    const md = [];
    md.push('# AES-GCM 三语言联合测试报告\n');
    md.push(`- 用例总数：**${total}**`);
    md.push(`- 成功用例：**${stats.success}**`);
    md.push(`- 失败用例：**${failed}**`);
    md.push(`- 成功率：**${(rate * 100).toFixed(6)}%**`);
    md.push(`- 失败率：**${((1 - rate) * 100).toFixed(6)}%**`);
    md.push(`- 单项校验：${passedChecks}/${checkTotal} 通过（${((passedChecks / checkTotal) * 100).toFixed(6)}%）`);
    md.push(`- 解密调用次数：${total * 9}，加密调用次数：${total * 3}，PBKDF2 派生次数：${total * 12}`);
    md.push(`- 随机种子：${meta.seed}（可复现）`);
    md.push(`- 总耗时：${elapsed.toFixed(1)}s，吞吐 ${(total / elapsed).toFixed(2)} 例/秒\n`);

    md.push('## 逐项校验通过率\n');
    md.push('| 校验项（加密方 → 解密方） | 通过 | 失败 | 通过率 |');
    md.push('| --- | ---: | ---: | ---: |');
    for (const [key, label] of Object.entries(checkNames)) {
        const ok = stats.checks[key];
        md.push(`| ${label} | ${ok} | ${total - ok} | ${((ok / total) * 100).toFixed(6)}% |`);
    }

    md.push('\n## 单次耗时（毫秒）\n');
    md.push('| 语言 | 加密均值 | 加密最大 | 解密均值 | 解密最大 |');
    md.push('| --- | ---: | ---: | ---: | ---: |');
    for (const lang of SOURCE_ORDER) {
        md.push(`| ${lang} | ${avg(stats.encMs[lang]).toFixed(2)} | ${max(stats.encMs[lang]).toFixed(2)} | ${avg(stats.decMs[lang]).toFixed(2)} | ${max(stats.decMs[lang]).toFixed(2)} |`);
    }

    md.push('\n## 错误分布\n');
    if (stats.errors.size === 0) {
        md.push('无。');
    } else {
        md.push('| 错误类型 | 次数 |');
        md.push('| --- | ---: |');
        for (const [k, v] of Array.from(stats.errors.entries()).sort()) {
            md.push(`| ${k} | ${v} |`);
        }
    }
    md.push('\n## 明细\n');
    md.push('逐用例明细见 `report.csv`（每例 9 项校验：3 个语言自身往返 + 6 组跨语言交叉解密）。');
    fs.writeFileSync(path.join(outDir, 'summary.md'), md.join('\n') + '\n', 'utf8');
}

function avg(arr) {
    if (!arr.length) return 0;
    let s = 0;
    for (const v of arr) s += v;
    return s / arr.length;
}

function max(arr) {
    let m = 0;
    for (const v of arr) if (v > m) m = v;
    return m;
}

function sha256(buf) {
    return crypto.createHash('sha256').update(buf).digest('hex');
}

async function* linesFrom(file) {
    const rl = readline.createInterface({
        input: fs.createReadStream(file, { encoding: 'utf8', highWaterMark: 1 << 20 }),
        crlfDelay: Infinity,
    });
    for await (const line of rl) yield line;
}

// ==================== 工具 ====================

function runCmd(name, cmd, args, opts = {}) {
    return new Promise((resolve, reject) => {
        const child = spawn(cmd, args, { cwd: opts.cwd || ROOT, env: process.env });
        let tail = '';
        const pump = (stream) => {
            stream.setEncoding('utf8');
            let rest = '';
            stream.on('data', (d) => {
                rest += d;
                let i;
                while ((i = rest.indexOf('\n')) >= 0) {
                    const line = rest.slice(0, i);
                    rest = rest.slice(i + 1);
                    if (line.trim()) console.log(`[${name}] ${line}`);
                }
            });
            stream.on('end', () => {
                if (rest.trim()) console.log(`[${name}] ${rest}`);
                tail = (tail + rest + '\n').slice(-4000);
            });
        };
        pump(child.stdout);
        pump(child.stderr);
        child.on('error', reject);
        child.on('close', (code) => {
            if (code === 0) resolve();
            else reject(new Error(`${name} exited with ${code}\n${tail}`));
        });
    });
}

function parseArgs(argv) {
    const o = {};
    for (let i = 0; i < argv.length; i++) {
        const a = argv[i];
        if (a.startsWith('--')) {
            const k = a.slice(2);
            o[k] = (argv[i + 1] && !argv[i + 1].startsWith('--')) ? argv[++i] : 'true';
        }
    }
    return o;
}

main();
