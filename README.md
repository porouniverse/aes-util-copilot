# aes-util-copilot 联合测试（Joint Test）

对 Go / Java / Node.js 三个 AES-GCM 实现做随机化联合测试：随机生成密码与明文，三个语言各自加密，
再由三个语言分别解密全部密文并按 UTF-8 字节逐一比对，验证三端互通与自身往返。

被测库（通过源码引用，不复制实现）：

| 语言 | 引用方式 | 路径 |
| --- | --- | --- |
| Go | `go.mod` 的 `replace` | `../aes-util-copilot@go` |
| Java | `javac -sourcepath` 直接编译源码 | `../aes-util-copilot@java/src/main/java` |
| Node.js | `require` | `../aes-util-copilot@js/aes-gcm-util.js` |

## 运行

```bash
node run.js                                   # 100000 例，输出到 out/
node run.js --total 200 --dir out-smoke       # 小规模冒烟
node run.js --total 100000 --seed 20261023    # 指定种子（默认可复现）
node run.js --workers-go 2 --workers-js 4 --workers-java 12
```

依赖：Go ≥ 1.24、JDK 8、Node.js ≥ 18。

## 流程

1. `cases.tsv`：按种子生成 N 组 `(password, plaintext)`，以 Base64 传输，覆盖 ASCII / 符号 / 中文 / 重音字符 / Emoji（代理对）/ 换行与制表符，明文长度 0–4096 字节。
2. `ct_{go,js,java}.tsv`：三个语言各自加密全部用例（Salt16 + IV12 + Ciphertext + Tag16 的 hex）。
3. `verify_{go,js,java}.tsv`：每个语言解密**全部三份**密文，与原文逐字节比对，输出 3 位掩码。
4. `report.csv` / `summary.csv` / `summary.md`：逐用例明细与统计。

每例共 9 项校验 = 3 个语言自身往返 + 6 组跨语言交叉解密；覆盖了「每个实现的加密都被另外两个实现解密验证」与「每个实现的解密都被另外两个实现的密文验证」。

## 产物

| 文件 | 说明 |
| --- | --- |
| `out/report.csv` | 逐用例明细（密码/明文摘要、密文长度、9 项校验结果、耗时、错误） |
| `out/summary.csv` | 指标化统计（成功率、失败率、逐项通过率、耗时） |
| `out/summary.md` | 人类可读报告 |
| `out/cases.tsv` / `out/ct_*.tsv` / `out/verify_*.tsv` | 中间数据，可用于复算 |
