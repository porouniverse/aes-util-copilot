'use strict';
/**
 * Node.js 侧联合测试驱动：调用真实库 ../../aes-util-copilot@js/aes-gcm-util.js
 *
 * 用法：
 *   node js/cli.js encrypt --cases out/cases.tsv --out out/ct_js.tsv --workers 4
 *   node js/cli.js verify  --cases out/cases.tsv --ct out/ct_go.tsv,out/ct_js.tsv,out/ct_java.tsv --out out/verify_js.tsv --workers 4
 *
 * 说明：被测库的 pbkdf2Sync 会阻塞事件循环，因此用 worker_threads 做多线程并行。
 */
const fs = require('fs');
const path = require('path');
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');

const LIB_PATH = path.join(__dirname, '..', '..', 'aes-util-copilot@js', 'aes-gcm-util.js');
const SOURCE_ORDER = ['go', 'js', 'java'];

if (isMainThread) {
    main();
} else {
    runWorker(workerData);
}

// ==================== 主线程 ====================

async function main() {
    const mode = process.argv[2];
    const opts = parseOpts(process.argv.slice(3));
    if (mode !== 'encrypt' && mode !== 'verify') {
        console.error('usage: cli.js encrypt|verify [options]');
        process.exit(2);
    }
    const workers = parseInt(opts.workers || '4', 10);
    const tasks = [];
    for (let i = 0; i < workers; i++) {
        tasks.push(spawnWorker({
            mode,
            casesPath: opts.cases,
            outPath: opts.out,
            ctPaths: opts.ct ? opts.ct.split(',') : [],
            idx: i,
            workers,
        }));
    }
    const results = await Promise.all(tasks);
    mergeParts(opts.out, results);
}

function spawnWorker(data) {
    return new Promise((resolve, reject) => {
        const w = new Worker(__filename, { workerData: data });
        w.on('message', (m) => resolve(m));
        w.on('error', reject);
        w.on('exit', (code) => { if (code !== 0) reject(new Error('worker exit ' + code)); });
    });
}

/** 合并各 worker 的分片输出，按 id 数值排序写出 */
function mergeParts(outPath, results) {
    const byId = new Map();
    for (const r of results) {
        const text = fs.readFileSync(r.partPath, 'utf8');
        for (const line of text.split('\n')) {
            if (!line) continue;
            const id = parseInt(line, 10);
            byId.set(id, line);
        }
        fs.unlinkSync(r.partPath);
    }
    const ids = Array.from(byId.keys()).sort((a, b) => a - b);
    const fd = fs.openSync(outPath, 'w');
    const buf = [];
    for (const id of ids) {
        buf.push(byId.get(id), '\n');
        if (buf.length >= 8192) {
            fs.writeSync(fd, buf.join(''));
            buf.length = 0;
        }
    }
    if (buf.length) fs.writeSync(fd, buf.join(''));
    fs.closeSync(fd);
    console.error(`[js][${path.basename(outPath)}] merged ${ids.length} rows`);
}

// ==================== worker 线程 ====================

function runWorker(data) {
    const lib = require(LIB_PATH);
    const { mode, casesPath, outPath, ctPaths, idx, workers } = data;
    const partPath = `${outPath}.part${idx}`;

    let ctSets = null;
    if (mode === 'verify') {
        ctSets = ctPaths.map((p) => loadCt(p, idx, workers));
    }

    const out = [];
    let done = 0;

    const rl = require('readline').createInterface({
        input: fs.createReadStream(casesPath, { encoding: 'utf8', highWaterMark: 1 << 20 }),
        crlfDelay: Infinity,
    });

    rl.on('line', (line) => {
        if (!line) return;
        if (line.startsWith('id\t')) return;

        const tab1 = line.indexOf('\t');
        const tab2 = line.indexOf('\t', tab1 + 1);
        const id = parseInt(line.slice(0, tab1), 10);
        if ((id - 1) % workers !== idx) return;
        const pw = Buffer.from(line.slice(tab1 + 1, tab2), 'base64').toString('utf8');
        const expected = Buffer.from(line.slice(tab2 + 1), 'base64').toString('utf8');

        if (mode === 'encrypt') {
            const start = process.hrtime.bigint();
            let ct = '';
            try {
                ct = lib.encryptHex(pw, expected);
            } catch (e) {
                console.error(`[js] ENCRYPT_ERROR id=${id} ${e.message}`);
            }
            const ms = Number(process.hrtime.bigint() - start) / 1e6;
            out.push(`${id}\t${ct}\t${ms.toFixed(3)}`);
        } else {
            let mask = 0;
            const errs = [];
            const ms = [0, 0, 0];
            for (let s = 0; s < SOURCE_ORDER.length; s++) {
                const start = process.hrtime.bigint();
                try {
                    const got = lib.decryptStr(pw, ctSets[s].get(id) || '');
                    if (got !== expected) errs.push(`${SOURCE_ORDER[s]}=plaintext mismatch`);
                    else mask |= (1 << s);
                } catch (e) {
                    errs.push(`${SOURCE_ORDER[s]}=${e.message}`);
                }
                ms[s] = Number(process.hrtime.bigint() - start) / 1e6;
            }
            const err = errs.length ? Buffer.from(errs.join('; '), 'utf8').toString('base64') : '-';
            out.push(`${id}\t${mask}\t${ms[0].toFixed(3)}\t${ms[1].toFixed(3)}\t${ms[2].toFixed(3)}\t${err}`);
        }

        done++;
        if (done % 5000 === 0) console.error(`[js][${mode}] ${done} (worker ${idx})`);
    });

    rl.on('close', () => {
        fs.writeFileSync(partPath, out.join('\n') + (out.length ? '\n' : ''), 'utf8');
        parentPort.postMessage({ partPath, count: out.length });
    });
}

/** 只保留属于本 worker 分片的密文，避免整表复制 */
function loadCt(ctPath, idx, workers) {
    const map = new Map();
    const text = fs.readFileSync(ctPath, 'utf8');
    for (const line of text.split('\n')) {
        if (!line) continue;
        if (line.startsWith('id\t')) continue;
        const tab = line.indexOf('\t');
        const id = parseInt(line.slice(0, tab), 10);
        if ((id - 1) % workers !== idx) continue;
        const tab2 = line.indexOf('\t', tab + 1);
        map.set(id, tab2 < 0 ? line.slice(tab + 1) : line.slice(tab + 1, tab2));
    }
    return map;
}

function parseOpts(argv) {
    const o = {};
    for (let i = 0; i < argv.length; i++) {
        if (argv[i].startsWith('--')) {
            const k = argv[i].slice(2);
            o[k] = (argv[i + 1] && !argv[i + 1].startsWith('--')) ? argv[++i] : 'true';
        }
    }
    return o;
}
