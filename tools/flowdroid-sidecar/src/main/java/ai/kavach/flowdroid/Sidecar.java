package ai.kavach.flowdroid;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import soot.Body;
import soot.G;
import soot.PackManager;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.ValueBox;
import soot.jimple.AssignStmt;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.IfStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.LookupSwitchStmt;
import soot.jimple.NewExpr;
import soot.jimple.Stmt;
import soot.jimple.TableSwitchStmt;
import soot.jimple.infoflow.InfoflowConfiguration.PathReconstructionMode;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.results.DataFlowResult;
import soot.jimple.infoflow.results.InfoflowResults;
import soot.jimple.infoflow.results.ResultSourceInfo;
import soot.jimple.infoflow.methodSummary.data.provider.EagerSummaryProvider;
import soot.jimple.infoflow.methodSummary.taintWrappers.SummaryTaintWrapper;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.MHGPostDominatorsFinder;
import soot.options.Options;

/** Minimal JSON boundary around pinned FlowDroid. No binaries are vendored. */
public final class Sidecar {
    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();
    private static final String SUMMARY_PATH = "summariesManual";
    private static final String SUMMARY_VERSION = "2.15.1";
    private static final List<String> STREAM_ENDPOINT_CONTRACTS = List.of(
        "<java.io.DataOutputStream: void writeBytes(java.lang.String)>",
        "<java.io.DataOutputStream: void writeChars(java.lang.String)>",
        "<java.io.DataOutputStream: void writeUTF(java.lang.String)>"
    );

    private Sidecar() {}

    public static void main(String[] args) throws Exception {
        Map<String, String> options = options(args);
        Path apk = required(options, "--apk");
        Path platforms = required(options, "--platforms");
        Path actionsPath = required(options, "--actions");
        Path output = required(options, "--output");
        if (options.getOrDefault("--mode", "taint").equals("actions")) {
            runActionsOnly(apk, platforms, actionsPath, output);
            return;
        }
        Path definitions = required(options, "--sources-sinks");
        Path categoriesPath = required(options, "--categories");
        long started = System.nanoTime();

        SetupApplication application = new SetupApplication(platforms.toFile(), apk.toFile());
        Path effectiveDefinitions = definitionsWithStreamContracts(definitions);
        application.getConfig().getAnalysisFileConfig().setSourceSinkFile(effectiveDefinitions.toFile());
        SummaryTaintWrapper summaryWrapper = new SummaryTaintWrapper(new EagerSummaryProvider(SUMMARY_PATH));
        application.setTaintWrapper(summaryWrapper);
        application.getConfig().getPathConfiguration().setPathReconstructionMode(PathReconstructionMode.Fast);
        int dataTimeout = Integer.parseInt(options.getOrDefault("--data-timeout", "300"));
        int callbackTimeout = Integer.parseInt(options.getOrDefault("--callback-timeout", "120"));
        int pathTimeout = Integer.parseInt(options.getOrDefault("--path-timeout", "120"));
        application.getConfig().setDataFlowTimeout(dataTimeout);
        application.getConfig().getCallbackConfig().setCallbackAnalysisTimeout(callbackTimeout);
        application.getConfig().getPathConfiguration().setPathReconstructionTimeout(pathTimeout);

        InfoflowResults results = application.runInfoflow();
        Map<String, String> categories = readStringMap(categoriesPath);
        IdentityHashMap<Unit, SootMethod> owners = statementOwners();
        List<Map<String, Object>> flows = new ArrayList<>();
        FlowDiagnostics diagnostics = new FlowDiagnostics();
        for (DataFlowResult result : results.getResultSet()) {
            diagnostics.observeRaw(result);
            try {
                Map<String, Object> recovered = flow(result, owners, categories, diagnostics);
                if (recovered != null) {
                    flows.add(recovered);
                    diagnostics.acceptedResultCount++;
                }
            } catch (RuntimeException exception) {
                diagnostics.pathReconstructionFailureCount++;
                diagnostics.reject("FLOW_CONVERSION_ERROR");
            }
        }
        flows.sort(Comparator.comparing(item -> GSON.toJson(item)));
        List<Map<String, Object>> actions = actions(readList(actionsPath), owners);

        Map<String, Object> root = new LinkedHashMap<>();
        root.put("schema_version", "flowdroid-sidecar-v1");
        root.put("apk_sha256", sha256(apk));
        root.put("status", status(results));
        root.put("flows", flows);
        root.put("actions", actions);
        root.put("issues", issues(results));
        double runtimeSeconds = (System.nanoTime() - started) / 1_000_000_000.0;
        root.put("diagnostics", diagnostics.toMap(status(results), runtimeSeconds));
        Map<String, Object> provenance = new LinkedHashMap<>();
        provenance.put("version", "2.15.1");
        Map<String, Object> effectiveConfig = new LinkedHashMap<>();
        effectiveConfig.put("definitions_sha256", sha256(definitions));
        effectiveConfig.put("categories_sha256", sha256(categoriesPath));
        effectiveConfig.put("actions_sha256", sha256(actionsPath));
        effectiveConfig.put("summary_provider", SUMMARY_PATH);
        effectiveConfig.put("summary_version", SUMMARY_VERSION);
        effectiveConfig.put("summary_data_output_sha256", summaryResourceSha256("java.io.DataOutputStream.xml"));
        effectiveConfig.put("stream_endpoint_contracts", STREAM_ENDPOINT_CONTRACTS);
        effectiveConfig.put("data_timeout", dataTimeout);
        effectiveConfig.put("callback_timeout", callbackTimeout);
        effectiveConfig.put("path_timeout", pathTimeout);
        effectiveConfig.put("exceptional_cfg", true);
        effectiveConfig.put("control_dependence", "postdominator-direct-v1");
        provenance.put("config_sha256", sha256Text(GSON.toJson(effectiveConfig)));
        provenance.put("runtime_seconds", runtimeSeconds);
        provenance.put("max_rss_kb", null);
        root.put("provenance", provenance);
        Files.createDirectories(output.toAbsolutePath().getParent());
        Files.writeString(output, GSON.toJson(root) + "\n", StandardCharsets.UTF_8);
    }

    private static void runActionsOnly(Path apk, Path platforms, Path actionsPath, Path output) throws Exception {
        long started = System.nanoTime();
        G.reset();
        Options.v().set_src_prec(Options.src_prec_apk);
        Options.v().set_process_dir(List.of(apk.toString()));
        Options.v().set_android_jars(platforms.toString());
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_output_format(Options.output_format_none);
        Options.v().set_whole_program(false);
        Scene.v().loadNecessaryClasses();
        PackManager.v().runPacks();
        IdentityHashMap<Unit, SootMethod> owners = statementOwners();
        List<Map<String, Object>> recovered = actions(readList(actionsPath), owners);
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("schema_version", "flowdroid-sidecar-v1");
        root.put("apk_sha256", sha256(apk));
        root.put("status", "SUCCESS");
        root.put("flows", List.of());
        root.put("actions", recovered);
        root.put("issues", List.of());
        Map<String, Object> provenance = new LinkedHashMap<>();
        provenance.put("version", "2.15.1-actions1");
        provenance.put("config_sha256", sha256(actionsPath));
        provenance.put("runtime_seconds", (System.nanoTime() - started) / 1_000_000_000.0);
        provenance.put("max_rss_kb", null);
        root.put("provenance", provenance);
        Files.createDirectories(output.toAbsolutePath().getParent());
        Files.writeString(output, GSON.toJson(root) + "\n", StandardCharsets.UTF_8);
    }

    private static List<Map<String, Object>> actions(
        List<Map<String, Object>> catalog, IdentityHashMap<Unit, SootMethod> owners
    ) {
        List<Map<String, Object>> output = new ArrayList<>();
        for (SootClass clazz : Scene.v().getApplicationClasses()) {
            for (SootMethod method : clazz.getMethods()) {
                if (!method.isConcrete()) continue;
                Body body;
                try { body = method.retrieveActiveBody(); }
                catch (RuntimeException ignored) { continue; }
                for (Unit unit : body.getUnits()) {
                    if (!(unit instanceof Stmt stmt) || !stmt.containsInvokeExpr()) continue;
                    InvokeExpr invoke = stmt.getInvokeExpr();
                    String signature = invoke.getMethodRef().getSignature();
                    Map<String, Object> rule = matchingRule(catalog, signature);
                    if (rule == null) continue;
                    String id = statementId(stmt, method, unit.hashCode());
                    Map<String, Object> endpoint = new LinkedHashMap<>();
                    endpoint.put("definition", signature);
                    endpoint.put("category", rule.get("endpoint_category"));
                    endpoint.put("statement", statement(stmt, method, id));
                    endpoint.put("access_path", null);
                    Map<String, Object> action = new LinkedHashMap<>();
                    action.put("endpoint", endpoint);
                    action.put("behavior_category", rule.get("behavior_category"));
                    action.put("argument_dependencies", argumentDefinitions(stmt, method));
                    action.put("controls", controls(List.of(stmt), owners, Map.of(stmt, id)));
                    action.put("component", component(method));
                    action.put("complete", true);
                    action.put("unresolved_calls", List.of());
                    output.add(action);
                }
            }
        }
        output.sort(Comparator.comparing(item -> GSON.toJson(item)));
        return output;
    }

    private static Map<String, Object> matchingRule(List<Map<String, Object>> catalog, String signature) {
        for (Map<String, Object> rule : catalog) {
            Object pattern = rule.get("signature_contains");
            if (pattern != null && signature.contains(pattern.toString())) return rule;
        }
        return null;
    }

    private static List<Map<String, Object>> argumentDefinitions(Stmt anchor, SootMethod method) {
        Set<Value> needed = new LinkedHashSet<>();
        for (ValueBox box : anchor.getUseBoxes()) needed.add(box.getValue());
        List<Map<String, Object>> output = new ArrayList<>();
        Unit cursor = method.getActiveBody().getUnits().getPredOf(anchor);
        int scanned = 0;
        while (cursor != null && !needed.isEmpty() && scanned++ < 128) {
            for (ValueBox box : cursor.getDefBoxes()) {
                if (needed.remove(box.getValue()) && cursor instanceof Stmt stmt) {
                    output.add(statement(stmt, method, statementId(stmt, method, -scanned)));
                    for (ValueBox use : cursor.getUseBoxes()) needed.add(use.getValue());
                }
            }
            cursor = method.getActiveBody().getUnits().getPredOf(cursor);
        }
        output.sort(Comparator.comparing(item -> item.get("statement_id").toString()));
        return output;
    }

    private static Map<String, Object> flow(
        DataFlowResult result, IdentityHashMap<Unit, SootMethod> owners, Map<String, String> categories,
        FlowDiagnostics diagnostics
    ) {
        ResultSourceInfo sourceInfo = result.getSource();
        Stmt sourceStmt = sourceInfo.getStmt();
        Stmt sinkStmt = result.getSink().getStmt();
        List<Stmt> path = new ArrayList<>();
        if (sourceInfo.getPath() != null) {
            for (Stmt stmt : sourceInfo.getPath()) path.add(stmt);
        } else diagnostics.pathNullCount++;
        if (!path.contains(sourceStmt)) path.add(0, sourceStmt);
        if (!path.contains(sinkStmt)) path.add(sinkStmt);

        List<Map<String, Object>> statements = new ArrayList<>();
        Map<Unit, String> ids = new IdentityHashMap<>();
        int index = 0;
        for (Stmt stmt : path) {
            String id = statementId(stmt, owners.get(stmt), index++);
            ids.put(stmt, id);
            statements.add(statement(stmt, owners.get(stmt), id));
        }
        Map<String, Object> value = new LinkedHashMap<>();
        String sourceDefinition = result.getSource().getDefinition().toString();
        String sinkDefinition = result.getSink().getDefinition().toString();
        String sourceCategory = contextualCategory(categories, sourceDefinition, "SOURCE", sourceStmt, owners.get(sourceStmt));
        String sinkCategory = contextualCategory(categories, sinkDefinition, "SINK", sinkStmt, owners.get(sinkStmt));
        if (sourceCategory == null && sinkCategory == null) {
            diagnostics.reject("UNMAPPED_SOURCE_AND_SINK");
            return null;
        }
        if (sourceCategory == null) {
            diagnostics.reject("UNMAPPED_SOURCE");
            return null;
        }
        if (sinkCategory == null) {
            diagnostics.reject(isStreamWrite(sinkDefinition)
                ? "STREAM_DESTINATION_NOT_CONSEQUENTIAL" : "UNMAPPED_SINK");
            return null;
        }
        value.put("source", endpoint(sourceDefinition, sourceCategory, ids.get(sourceStmt), sourceInfo.getAccessPath()));
        Map<String, Object> sink = endpoint(sinkDefinition, sinkCategory, ids.get(sinkStmt), result.getSink().getAccessPath());
        if (isStreamWrite(sinkDefinition)) {
            sink.put("raw_operation", sinkDefinition.contains("DataOutput") ? "DATA_OUTPUT_WRITE" : "STREAM_WRITE");
            sink.put("destination", streamDestination(sinkStmt, owners.get(sinkStmt)));
        }
        value.put("sink", sink);
        value.put("statements", statements);
        value.put("controls", controls(path, owners, ids));
        value.put("call_sites", List.of());
        value.put("component", component(owners.get(sourceStmt)));
        value.put("complete", sourceInfo.getPath() != null);
        value.put("unresolved_calls", List.of());
        return value;
    }

    private static List<Map<String, Object>> controls(
        List<Stmt> path, IdentityHashMap<Unit, SootMethod> owners, Map<Unit, String> pathIds
    ) {
        Map<SootMethod, List<Unit>> targets = new LinkedHashMap<>();
        for (Stmt stmt : path) {
            SootMethod method = owners.get(stmt);
            if (method != null) targets.computeIfAbsent(method, ignored -> new ArrayList<>()).add(stmt);
        }
        List<Map<String, Object>> output = new ArrayList<>();
        for (Map.Entry<SootMethod, List<Unit>> entry : targets.entrySet()) {
            SootMethod method = entry.getKey();
            if (!method.hasActiveBody()) continue;
            ExceptionalUnitGraph graph = new ExceptionalUnitGraph(method.getActiveBody());
            MHGPostDominatorsFinder<Unit> postdom = new MHGPostDominatorsFinder<>(graph);
            for (Unit branch : graph) {
                if (!(branch instanceof IfStmt || branch instanceof LookupSwitchStmt || branch instanceof TableSwitchStmt)) continue;
                List<Unit> immediate = new ArrayList<>();
                for (Unit target : entry.getValue()) {
                    if (directlyControls(branch, target, graph, postdom)) immediate.add(target);
                }
                if (immediate.isEmpty()) continue;
                String predicateId = statementId((Stmt) branch, method, branch.hashCode());
                Map<String, Object> control = new LinkedHashMap<>();
                control.put("predicate", statement((Stmt) branch, method, predicateId));
                control.put("controls_statement_ids", immediate.stream().map(pathIds::get).filter(java.util.Objects::nonNull).sorted().toList());
                control.put("operand_definitions", operandDefinitions(branch, method));
                output.add(control);
            }
        }
        output.sort(Comparator.comparing(item -> GSON.toJson(item)));
        return output;
    }

    private static List<Map<String, Object>> operandDefinitions(Unit branch, SootMethod method) {
        Set<Value> needed = new LinkedHashSet<>();
        for (ValueBox box : branch.getUseBoxes()) needed.add(box.getValue());
        List<Map<String, Object>> output = new ArrayList<>();
        Unit cursor = method.getActiveBody().getUnits().getPredOf(branch);
        int scanned = 0;
        while (cursor != null && !needed.isEmpty() && scanned++ < 64) {
            for (ValueBox box : cursor.getDefBoxes()) {
                if (needed.remove(box.getValue()) && cursor instanceof Stmt stmt) {
                    output.add(statement(stmt, method, statementId(stmt, method, -scanned)));
                }
            }
            cursor = method.getActiveBody().getUnits().getPredOf(cursor);
        }
        output.sort(Comparator.comparing(item -> item.get("statement_id").toString()));
        return output;
    }

    private static boolean directlyControls(
        Unit branch, Unit target, ExceptionalUnitGraph graph, MHGPostDominatorsFinder<Unit> postdom
    ) {
        Unit stop = postdom.getImmediateDominator(branch);
        for (Unit successor : graph.getSuccsOf(branch)) {
            if (postdom.isDominatedBy(successor, branch)) continue;
            Set<Unit> seen = new LinkedHashSet<>();
            List<Unit> work = new ArrayList<>();
            work.add(successor);
            while (!work.isEmpty()) {
                Unit current = work.remove(work.size() - 1);
                if (current == stop || !seen.add(current)) continue;
                if (current == target) return true;
                work.addAll(graph.getSuccsOf(current));
            }
        }
        return false;
    }

    private static IdentityHashMap<Unit, SootMethod> statementOwners() {
        IdentityHashMap<Unit, SootMethod> owners = new IdentityHashMap<>();
        for (SootClass clazz : Scene.v().getApplicationClasses()) {
            for (SootMethod method : clazz.getMethods()) {
                if (!method.isConcrete()) continue;
                try {
                    Body body = method.retrieveActiveBody();
                    for (Unit unit : body.getUnits()) owners.put(unit, method);
                } catch (RuntimeException ignored) { }
            }
        }
        return owners;
    }

    private static Map<String, Object> statement(Stmt stmt, SootMethod method, String id) {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("statement_id", id);
        value.put("method_signature", method == null ? "<unknown>" : method.getSignature());
        value.put("jimple", stmt.toString());
        int offset = stmt.getJavaSourceStartLineNumber();
        value.put("line_number", offset > 0 ? offset : null);
        value.put("dex_offset", null);
        value.put("tags", stmt.getTags().stream().map(Object::toString).sorted().toList());
        value.put("exception_context", List.of());
        value.put("monitor_context", null);
        return value;
    }

    private static Map<String, Object> endpoint(String definition, String category, String id, Object accessPath) {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("definition", definition);
        value.put("category", category);
        value.put("statement_id", id);
        value.put("access_path", accessPath == null ? null : accessPath.toString());
        return value;
    }

    private static Map<String, Object> component(SootMethod method) {
        if (method == null) return null;
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("component_type", "unknown");
        value.put("component_name", method.getDeclaringClass().getName());
        value.put("callback", method.getName());
        value.put("exported", null);
        return value;
    }

    private static String category(Map<String, String> categories, String definition, String role) {
        String direct = categories.get(definition);
        if (direct != null) return direct;
        for (Map.Entry<String, String> entry : categories.entrySet()) {
            if (definition.contains(entry.getKey())) return entry.getValue();
        }
        for (String signature : STREAM_ENDPOINT_CONTRACTS) {
            if (definition.contains(signature)) return "STREAM_OUTPUT";
        }
        return "UNMAPPED_" + role;
    }

    private static String contextualCategory(
        Map<String, String> categories, String definition, String role, Stmt statement, SootMethod owner
    ) {
        String value = category(categories, definition, role);
        String body = ownerBody(owner).toLowerCase();
        if (value.equals("PROVIDER_CURSOR")) {
            if (containsAny(body, "contactscontract", "content://contacts", "com.android.contacts")) return "CONTACT_INFORMATION";
            if (containsAny(body, "calllog$calls", "calllog.calls", "content://call_log")) return "CALL_LOG_INFORMATION";
            if (containsAny(body, "calendarcontract", "content://com.android.calendar")) return "CALENDAR_INFORMATION";
            if (containsAny(body, "telephony$sms", "telephony.sms", "content://sms", "content://mms")) return "SMS_MMS";
            if (containsAny(body, "mediastore", "content://media")) return "MEDIA_INFORMATION";
            return null;
        }
        if (value.equals("SETTINGS_VALUE")) {
            return containsAny(body, "android_id", "settings$secure: java.lang.string android_id")
                ? "APP_IDENTIFIER" : null;
        }
        if (value.equals("STREAM_OUTPUT")) {
            String destination = streamDestination(statement, owner);
            if (destination.equals("NETWORK")) return "NETWORK";
            if (destination.equals("SHARED_FILE")) return "SHARED_FILE";
            return null;
        }
        return value.startsWith("UNMAPPED_") ? null : value;
    }

    private static String ownerBody(SootMethod method) {
        if (method == null || !method.isConcrete()) return "";
        try { return method.retrieveActiveBody().toString(); }
        catch (RuntimeException ignored) { return ""; }
    }

    private static boolean containsAny(String value, String... needles) {
        for (String needle : needles) if (value.contains(needle)) return true;
        return false;
    }

    /** Adds the small semantic DataOutput contract family without mutating the caller's catalogue. */
    private static Path definitionsWithStreamContracts(Path definitions) throws IOException {
        if (definitions.getFileName().toString().toLowerCase().endsWith(".xml")) return definitions;
        String original = Files.readString(definitions, StandardCharsets.UTF_8);
        StringBuilder effective = new StringBuilder(original);
        for (String signature : STREAM_ENDPOINT_CONTRACTS) {
            if (!original.contains(signature)) effective.append('\n').append(signature).append(" -> _SINK_");
        }
        Path generated = Files.createTempFile("kavach-flowdroid-sources-sinks-", ".txt");
        Files.writeString(generated, effective.append('\n').toString(), StandardCharsets.UTF_8);
        generated.toFile().deleteOnExit();
        return generated;
    }

    private static String summaryResourceSha256(String name) throws Exception {
        String resource = SUMMARY_PATH + "/" + name;
        try (InputStream input = Sidecar.class.getClassLoader().getResourceAsStream(resource)) {
            if (input == null) throw new IllegalStateException("Missing pinned StubDroid summary resource: " + resource);
            return hex(MessageDigest.getInstance("SHA-256").digest(input.readAllBytes()));
        }
    }

    private static boolean isStreamWrite(String definition) {
        return definition.contains("java.io.OutputStream") || definition.contains("java.io.Writer")
            || definition.contains("java.io.PrintWriter") || definition.contains("java.io.DataOutput");
    }

    /** Bounded local def-use recovery for the receiver's underlying stream. */
    private static String streamDestination(Stmt sink, SootMethod owner) {
        if (owner == null || !owner.isConcrete() || !sink.containsInvokeExpr()
            || !(sink.getInvokeExpr() instanceof InstanceInvokeExpr invoke)) return "UNKNOWN_DESTINATION";
        return traceStreamValue(invoke.getBase(), sink, owner, new LinkedHashSet<>(), 0);
    }

    private static String traceStreamValue(
        Value value, Unit before, SootMethod owner, Set<String> visited, int depth
    ) {
        if (depth > 12 || !visited.add(value + "@" + before.hashCode())) return "UNKNOWN_DESTINATION";
        Unit cursor = owner.getActiveBody().getUnits().getPredOf(before);
        int scanned = 0;
        while (cursor != null && scanned++ < 128) {
            if (cursor instanceof Stmt stmt && stmt.containsInvokeExpr()
                && stmt.getInvokeExpr() instanceof InstanceInvokeExpr call && call.getBase().equivTo(value)) {
                String signature = call.getMethodRef().getSignature();
                if (signature.contains("java.io.DataOutputStream: void <init>")
                    || signature.contains("java.io.FilterOutputStream: void <init>")
                    || signature.contains("java.io.BufferedOutputStream: void <init>")
                    || signature.contains("java.io.PrintWriter: void <init>(java.io.OutputStream)")) {
                    if (call.getArgCount() > 0)
                        return traceStreamValue(call.getArg(0), cursor, owner, visited, depth + 1);
                }
                String direct = destinationForSignature(signature);
                if (!direct.equals("UNKNOWN_DESTINATION")) return direct;
            }
            if (cursor instanceof AssignStmt assign && assign.getLeftOp().equivTo(value)) {
                Value right = assign.getRightOp();
                if (right instanceof InvokeExpr call) {
                    String direct = destinationForSignature(call.getMethodRef().getSignature());
                    if (!direct.equals("UNKNOWN_DESTINATION")) return direct;
                }
                if (right instanceof NewExpr allocation) {
                    String type = allocation.getBaseType().getClassName();
                    if (type.equals("java.io.FileOutputStream")) return "FILE";
                }
                return traceStreamValue(right, cursor, owner, visited, depth + 1);
            }
            cursor = owner.getActiveBody().getUnits().getPredOf(cursor);
        }
        return "UNKNOWN_DESTINATION";
    }

    private static String destinationForSignature(String signature) {
        String lower = signature.toLowerCase();
        if (containsAny(lower, "java.net.urlconnection: java.io.outputstream getoutputstream",
            "java.net.httpurlconnection: java.io.outputstream getoutputstream",
            "java.net.socket: java.io.outputstream getoutputstream")) return "NETWORK";
        if (lower.contains("java.io.fileoutputstream: void <init>")) return "FILE";
        if (containsAny(lower, "getexternalfilesdir", "getexternalcachedir", "mediastore", "documentscontract"))
            return "SHARED_FILE";
        return "UNKNOWN_DESTINATION";
    }

    private static String statementId(Stmt stmt, SootMethod method, int ordinal) {
        return sha256Text((method == null ? "<unknown>" : method.getSignature()) + "\n" + stmt + "\n" + ordinal).substring(0, 24);
    }

    private static String status(InfoflowResults results) {
        if (results.wasTerminatedOutOfMemory()) return "PARTIAL_OOM";
        if (results.wasAbortedTimeout()) return "PARTIAL_TIMEOUT";
        return "SUCCESS";
    }

    private static List<Map<String, Object>> issues(InfoflowResults results) {
        List<Map<String, Object>> issues = new ArrayList<>();
        if (results.getExceptions() != null) {
            for (String exception : results.getExceptions()) {
                issues.add(Map.of("code", "FLOWDROID_EXCEPTION", "message", exception, "phase", "managed", "severity", "warning"));
            }
        }
        if (results.wasAbortedTimeout()) issues.add(Map.of("code", "FLOWDROID_TIMEOUT", "message", "FlowDroid returned partial results after a timeout", "phase", "managed", "severity", "warning"));
        if (results.wasTerminatedOutOfMemory()) issues.add(Map.of("code", "FLOWDROID_OOM", "message", "FlowDroid returned partial results after OOM", "phase", "managed", "severity", "error"));
        return issues;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, String> readStringMap(Path path) throws IOException {
        return GSON.fromJson(Files.readString(path), Map.class);
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> readList(Path path) throws IOException {
        return GSON.fromJson(Files.readString(path), List.class);
    }

    private static Map<String, String> options(String[] args) {
        Map<String, String> output = new HashMap<>();
        for (int index = 0; index < args.length; index += 2) {
            if (index + 1 >= args.length) throw new IllegalArgumentException("missing value for " + args[index]);
            output.put(args[index], args[index + 1]);
        }
        return output;
    }

    private static Path required(Map<String, String> options, String name) {
        String value = options.get(name);
        if (value == null) throw new IllegalArgumentException("missing " + name);
        return Path.of(value);
    }

    private static String sha256(Path path) throws Exception {
        return hex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)));
    }

    private static String sha256Text(String value) {
        try { return hex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (Exception exception) { throw new IllegalStateException(exception); }
    }

    private static String hex(byte[] value) {
        StringBuilder builder = new StringBuilder();
        for (byte item : value) builder.append(String.format("%02x", item));
        return builder.toString();
    }

    private static final class FlowDiagnostics {
        private int rawResultCount;
        private int acceptedResultCount;
        private int rejectedResultCount;
        private int pathNullCount;
        private int pathReconstructionFailureCount;
        private final Map<String, Integer> rejectionReasonCounts = new LinkedHashMap<>();
        private final Map<String, Integer> sourceOccurrenceCounts = new LinkedHashMap<>();
        private final Map<String, Integer> sinkOccurrenceCounts = new LinkedHashMap<>();

        private void observeRaw(DataFlowResult result) {
            rawResultCount++;
            increment(sourceOccurrenceCounts, result.getSource().getDefinition().toString());
            increment(sinkOccurrenceCounts, result.getSink().getDefinition().toString());
        }

        private void reject(String reason) {
            rejectedResultCount++;
            increment(rejectionReasonCounts, reason);
        }

        private static void increment(Map<String, Integer> counts, String key) {
            counts.put(key, counts.getOrDefault(key, 0) + 1);
        }

        private Map<String, Object> toMap(String terminationState, double runtimeSeconds) {
            Map<String, Object> value = new LinkedHashMap<>();
            value.put("raw_result_count", rawResultCount);
            value.put("accepted_result_count", acceptedResultCount);
            value.put("rejected_result_count", rejectedResultCount);
            value.put("rejection_reason_counts", sortedCounts(rejectionReasonCounts));
            value.put("path_null_count", pathNullCount);
            value.put("path_reconstruction_failure_count", pathReconstructionFailureCount);
            value.put("source_occurrence_counts", sortedCounts(sourceOccurrenceCounts));
            value.put("sink_occurrence_counts", sortedCounts(sinkOccurrenceCounts));
            value.put("termination_state", terminationState);
            value.put("performance", Map.of("runtime_seconds", runtimeSeconds));
            return value;
        }

        private static Map<String, Integer> sortedCounts(Map<String, Integer> counts) {
            Map<String, Integer> sorted = new LinkedHashMap<>();
            counts.entrySet().stream().sorted(Map.Entry.comparingByKey())
                .forEach(entry -> sorted.put(entry.getKey(), entry.getValue()));
            return sorted;
        }
    }
}
