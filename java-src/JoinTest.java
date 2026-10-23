// Java 侧联合测试驱动：调用真实库 com.gust.cafe.copilot.util.AesGcmUtils
//
// 用法：
//
//	JoinTest encrypt --cases out/cases.tsv --out out/ct_java.tsv --workers 12
//	JoinTest verify  --cases out/cases.tsv --ct out/ct_go.tsv,out/ct_js.tsv,out/ct_java.tsv --out out/verify_java.tsv --workers 12
import com.gust.cafe.copilot.util.AesGcmUtils;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

public class JoinTest {

    /** 固定三语言密文的顺序，verify 输出的 mask 位序与之一一对应 */
    static final String[] SOURCE_ORDER = {"go", "js", "java"};

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("usage: JoinTest encrypt|verify [options]");
            System.exit(2);
        }
        String mode = args[0];
        Map<String, String> opts = parseOpts(args);
        List<String[]> cases = readCases(opts.get("cases"));
        int workers = Integer.parseInt(opts.containsKey("workers") ? opts.get("workers") : "4");

        if ("encrypt".equals(mode)) {
            encrypt(cases, workers, opts.get("out"));
        } else if ("verify".equals(mode)) {
            verify(cases, workers, opts.get("ct").split(","), opts.get("out"));
        } else {
            System.err.println("unknown mode: " + mode);
            System.exit(2);
        }
    }

    // ---------------- 加密 ----------------

    static void encrypt(List<String[]> cases, int workers, String outPath) throws Exception {
        int n = cases.size();
        String[] cts = new String[n];
        String[] errs = new String[n];
        double[] ms = new double[n];

        final AtomicInteger next = new AtomicInteger(0);
        final AtomicInteger done = new AtomicInteger(0);
        ExecutorService pool = Executors.newFixedThreadPool(workers);
        List<Future<?>> futures = new ArrayList<Future<?>>();
        for (int t = 0; t < workers; t++) {
            futures.add(pool.submit(new Runnable() {
                @Override
                public void run() {
                    int i;
                    while ((i = next.getAndIncrement()) < n) {
                        String[] row = cases.get(i);
                        String pw = decodeUtf8(row[1]);
                        String pt = decodeUtf8(row[2]);
                        long start = System.nanoTime();
                        try {
                            cts[i] = AesGcmUtils.encryptHex(pw, pt);
                        } catch (Throwable e) {
                            errs[i] = e.getClass().getSimpleName() + ": " + e.getMessage();
                        }
                        ms[i] = (System.nanoTime() - start) / 1e6;
                        progress("java", "encrypt", done.incrementAndGet(), n);
                    }
                }
            }));
        }
        for (Future<?> f : futures) {
            f.get();
        }
        pool.shutdown();

        BufferedWriter w = writer(outPath);
        try {
            for (int i = 0; i < n; i++) {
                w.write(cases.get(i)[0]);
                w.write('\t');
                w.write(cts[i] == null ? "" : cts[i]);
                w.write('\t');
                w.write(String.format("%.3f", ms[i]));
                w.write('\n');
                if (errs[i] != null) {
                    // 加密异常极少见，单独记录到同名 .err 文件
                    System.err.println("ENCRYPT_ERROR id=" + cases.get(i)[0] + " " + errs[i]);
                }
            }
        } finally {
            w.close();
        }
    }

    // ---------------- 交叉解密验证 ----------------

    static void verify(List<String[]> cases, int workers, String[] ctPaths, String outPath) throws Exception {
        int n = cases.size();
        int maxId = 0;
        for (String[] row : cases) {
            int id = Integer.parseInt(row[0]);
            if (id > maxId) {
                maxId = id;
            }
        }

        String[][] ctSets = new String[SOURCE_ORDER.length][];
        for (int s = 0; s < SOURCE_ORDER.length; s++) {
            ctSets[s] = readCt(ctPaths[s], maxId);
        }

        int[] masks = new int[n];
        double[][] msBySource = new double[n][3];
        String[] errs = new String[n];

        final AtomicInteger next = new AtomicInteger(0);
        final AtomicInteger done = new AtomicInteger(0);
        ExecutorService pool = Executors.newFixedThreadPool(workers);
        List<Future<?>> futures = new ArrayList<Future<?>>();
        for (int t = 0; t < workers; t++) {
            futures.add(pool.submit(new Runnable() {
                @Override
                public void run() {
                    int i;
                    while ((i = next.getAndIncrement()) < n) {
                        String[] row = cases.get(i);
                        int id = Integer.parseInt(row[0]);
                        String pw = decodeUtf8(row[1]);
                        String expected = decodeUtf8(row[2]);
                        int mask = 0;
                        StringBuilder msg = new StringBuilder();
                        for (int s = 0; s < SOURCE_ORDER.length; s++) {
                            long start = System.nanoTime();
                            String got = null;
                            String fail = null;
                            try {
                                got = AesGcmUtils.decryptStr(pw, ctSets[s][id]);
                            } catch (Throwable e) {
                                fail = e.getClass().getSimpleName() + ": " + e.getMessage();
                            }
                            msBySource[i][s] = (System.nanoTime() - start) / 1e6;
                            if (fail != null) {
                                appendErr(msg, SOURCE_ORDER[s], fail);
                            } else if (!expected.equals(got)) {
                                appendErr(msg, SOURCE_ORDER[s], "plaintext mismatch");
                            } else {
                                mask |= 1 << s;
                            }
                        }
                        masks[i] = mask;
                        if (msg.length() > 0) {
                            errs[i] = msg.toString();
                        }
                        progress("java", "verify", done.incrementAndGet(), n);
                    }
                }
            }));
        }
        for (Future<?> f : futures) {
            f.get();
        }
        pool.shutdown();

        BufferedWriter w = writer(outPath);
        try {
            for (int i = 0; i < n; i++) {
                String e = errs[i] == null ? "-"
                        : Base64.getEncoder().encodeToString(errs[i].getBytes(StandardCharsets.UTF_8));
                w.write(cases.get(i)[0]);
                w.write('\t');
                w.write(Integer.toString(masks[i]));
                w.write('\t');
                w.write(String.format("%.3f", msBySource[i][0]));
                w.write('\t');
                w.write(String.format("%.3f", msBySource[i][1]));
                w.write('\t');
                w.write(String.format("%.3f", msBySource[i][2]));
                w.write('\t');
                w.write(e);
                w.write('\n');
            }
        } finally {
            w.close();
        }
    }

    // ---------------- IO ----------------

    static List<String[]> readCases(String path) throws Exception {
        List<String[]> rows = new ArrayList<String[]>();
        BufferedReader r = new BufferedReader(
                new InputStreamReader(new FileInputStream(path), StandardCharsets.UTF_8), 1 << 20);
        try {
            String line;
            boolean first = true;
            while ((line = r.readLine()) != null) {
                if (first) {
                    first = false;
                    if (line.startsWith("id\t")) {
                        continue;
                    }
                }
                String[] parts = line.split("\t", 3);
                if (parts.length != 3) {
                    throw new IllegalStateException("bad cases line: " + line.substring(0, Math.min(80, line.length())));
                }
                rows.add(parts);
            }
        } finally {
            r.close();
        }
        return rows;
    }

    static String[] readCt(String path, int maxId) throws Exception {
        String[] out = new String[maxId + 1];
        BufferedReader r = new BufferedReader(
                new InputStreamReader(new FileInputStream(path), StandardCharsets.UTF_8), 1 << 20);
        try {
            String line;
            boolean first = true;
            while ((line = r.readLine()) != null) {
                if (first) {
                    first = false;
                    if (line.startsWith("id\t")) {
                        continue;
                    }
                }
                int tab = line.indexOf('\t');
                if (tab < 0) {
                    throw new IllegalStateException("bad ct line in " + path);
                }
                int id = Integer.parseInt(line.substring(0, tab));
                int tab2 = line.indexOf('\t', tab + 1);
                out[id] = tab2 < 0 ? line.substring(tab + 1) : line.substring(tab + 1, tab2);
            }
        } finally {
            r.close();
        }
        return out;
    }

    static BufferedWriter writer(String path) throws Exception {
        File f = new File(path);
        if (f.getParentFile() != null) {
            f.getParentFile().mkdirs();
        }
        return new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(f), StandardCharsets.UTF_8), 1 << 20);
    }

    static String decodeUtf8(String b64) {
        return new String(Base64.getDecoder().decode(b64), StandardCharsets.UTF_8);
    }

    static void appendErr(StringBuilder sb, String src, String msg) {
        if (sb.length() > 0) {
            sb.append("; ");
        }
        sb.append(src).append('=').append(msg);
    }

    static void progress(String lang, String phase, int done, int total) {
        if (done % 5000 == 0 || done == total) {
            System.err.println("[" + lang + "][" + phase + "] " + done + "/" + total);
        }
    }

    static Map<String, String> parseOpts(String[] args) {
        Map<String, String> o = new HashMap<String, String>();
        for (int i = 1; i < args.length; i++) {
            if (args[i].startsWith("--")) {
                String k = args[i].substring(2);
                if (i + 1 < args.length && !args[i + 1].startsWith("--")) {
                    o.put(k, args[i + 1]);
                    i++;
                } else {
                    o.put(k, "true");
                }
            }
        }
        return o;
    }
}
