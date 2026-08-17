// Collect bounded JNI-relevant evidence for Kavach Stage 1.
// @category Kavach

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.util.DefinedStringIterator;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class KavachNativeEvidence extends GhidraScript {
    private static final int MAX_FUNCTIONS = 32;
    private static final int DECOMPILE_TIMEOUT_SECONDS = 30;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 3) throw new IllegalArgumentException("expected output.json debug-dir config-sha256");
        Path output = Path.of(args[0]);
        Path debugDir = Path.of(args[1]);
        String configSha256 = args[2];
        Files.createDirectories(output.toAbsolutePath().getParent());
        Files.createDirectories(debugDir);

        long started = System.nanoTime();
        List<Function> seeds = selectSeeds();
        List<Map<String, Object>> functions = new ArrayList<>();
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        try {
            for (Function function : seeds) {
                if (monitor.isCancelled()) break;
                functions.add(evidence(function, decompiler, debugDir));
            }
        } finally {
            decompiler.dispose();
        }

        Map<String, Object> root = new LinkedHashMap<>();
        root.put("schema_version", "ghidra-sidecar-v1");
        root.put("library_sha256", sha256(Path.of(currentProgram.getExecutablePath())));
        root.put("abi", currentProgram.getLanguageID().toString());
        root.put("status", monitor.isCancelled() ? "PARTIAL_TIMEOUT" : "SUCCESS");
        root.put("functions", functions);
        root.put("issues", List.of());
        Map<String, Object> provenance = new LinkedHashMap<>();
        provenance.put("version", getVersion());
        provenance.put("config_sha256", configSha256);
        provenance.put("runtime_seconds", (System.nanoTime() - started) / 1_000_000_000.0);
        provenance.put("max_rss_kb", null);
        root.put("provenance", provenance);
        Files.writeString(output, json(root) + "\n", StandardCharsets.UTF_8);
    }

    private List<Function> selectSeeds() {
        List<Function> preferred = new ArrayList<>();
        List<Function> fallback = new ArrayList<>();
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext()) {
            Function function = iterator.next();
            String name = function.getName();
            if (name.startsWith("Java_") || name.equals("JNI_OnLoad") || name.contains("RegisterNatives")) preferred.add(function);
            else if (!function.isExternal()) fallback.add(function);
        }
        Comparator<Function> order = Comparator.comparing((Function item) -> item.getName())
            .thenComparing(item -> item.getEntryPoint().toString());
        preferred.sort(order);
        fallback.sort(order);
        LinkedHashSet<Function> selected = new LinkedHashSet<>(preferred);
        if (selected.isEmpty()) selected.addAll(fallback.subList(0, Math.min(8, fallback.size())));
        for (Function seed : List.copyOf(selected)) {
            selected.addAll(seed.getCalledFunctions(monitor));
            if (selected.size() >= MAX_FUNCTIONS) break;
        }
        return selected.stream().sorted(order).limit(MAX_FUNCTIONS).toList();
    }

    private Map<String, Object> evidence(Function function, DecompInterface decompiler, Path debugDir) throws Exception {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("function_id", function.getName());
        DecompileResults result = decompiler.decompileFunction(function, DECOMPILE_TIMEOUT_SECONDS, monitor);
        String code = result.decompileCompleted() ? result.getDecompiledFunction().getC() : null;
        value.put("decompiled_code", code);
        Set<Function> called = function.getCalledFunctions(monitor);
        List<String> calls = called.stream().map(Function::getName).sorted().toList();
        value.put("calls", calls);
        Set<String> externalNames = new LinkedHashSet<>();
        SymbolIterator externals = currentProgram.getSymbolTable().getExternalSymbols();
        while (externals.hasNext()) externalNames.add(externals.next().getName());
        value.put("imports", calls.stream().filter(externalNames::contains).toList());
        value.put("strings", referencedStrings(function));

        if (result.decompileCompleted()) {
            StringBuilder pcodeBuilder = new StringBuilder();
            var operations = result.getHighFunction().getPcodeOps();
            while (operations.hasNext()) {
                PcodeOpAST operation = operations.next();
                pcodeBuilder.append(operation).append('\n');
            }
            String pcode = pcodeBuilder.toString();
            byte[] bytes = pcode.getBytes(StandardCharsets.UTF_8);
            String digest = hex(MessageDigest.getInstance("SHA-256").digest(bytes));
            Files.write(debugDir.resolve(digest + ".pcode.txt"), bytes);
            value.put("raw_pcode_debug_ref", "sha256:" + digest);
        }
        value.put("full_analysis_debug_ref", null);
        return value;
    }

    private List<String> referencedStrings(Function function) {
        Set<String> output = new LinkedHashSet<>();
        for (Data data : DefinedStringIterator.forProgram(currentProgram)) {
            var references = currentProgram.getReferenceManager().getReferencesTo(data.getAddress());
            while (references.hasNext()) {
                Reference reference = references.next();
                if (function.getBody().contains(reference.getFromAddress())) {
                    Object value = data.getValue();
                    if (value != null) output.add(value.toString());
                    break;
                }
            }
        }
        return output.stream().sorted().limit(64).toList();
    }

    private String getVersion() {
        return ghidra.framework.Application.getApplicationVersion();
    }

    private static String sha256(Path path) throws Exception {
        return hex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)));
    }

    private static String hex(byte[] value) {
        StringBuilder builder = new StringBuilder();
        for (byte item : value) builder.append(String.format("%02x", item));
        return builder.toString();
    }

    private static String json(Object value) {
        if (value == null) return "null";
        if (value instanceof String text) return quote(text);
        if (value instanceof Number || value instanceof Boolean) return value.toString();
        if (value instanceof Map<?, ?> map) {
            List<String> items = new ArrayList<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) items.add(json(entry.getKey().toString()) + ":" + json(entry.getValue()));
            return "{" + String.join(",", items) + "}";
        }
        if (value instanceof Iterable<?> iterable) {
            List<String> items = new ArrayList<>();
            for (Object item : iterable) items.add(json(item));
            return "[" + String.join(",", items) + "]";
        }
        return json(value.toString());
    }

    private static String quote(String text) {
        StringBuilder output = new StringBuilder("\"");
        for (int index = 0; index < text.length(); index++) {
            char value = text.charAt(index);
            switch (value) {
                case '\\' -> output.append("\\\\");
                case '\"' -> output.append("\\\"");
                case '\n' -> output.append("\\n");
                case '\r' -> output.append("\\r");
                case '\t' -> output.append("\\t");
                case '\b' -> output.append("\\b");
                case '\f' -> output.append("\\f");
                default -> {
                    if (value < 0x20) output.append(String.format("\\u%04x", (int) value));
                    else output.append(value);
                }
            }
        }
        return output.append('\"').toString();
    }
}
