package burp;

import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import javax.management.*;

/** Optional legacy-API companion. No network listener and no automatic scan on load. */
public final class BurpExtender implements IBurpExtender, IExtensionStateListener, DynamicMBean {
    public static final String OBJECT_NAME = "net.portswigger.mcp:type=LegacyScanBridge";
    private final String bridgeId = UUID.randomUUID().toString();
    private final Map<String, Entry> entries = new LinkedHashMap<>();
    private final Map<String, String> operations = new HashMap<>();
    private IBurpExtenderCallbacks callbacks;
    private boolean loaded;
    private static final int MAX_ENTRIES = 256;

    private static final class Entry {
        final String id = UUID.randomUUID().toString();
        final String createdAt = Instant.now().toString();
        final String fingerprint;
        final String operationId, host, protocol, method, path;
        final int port;
        IScanQueueItem item;
        boolean cancelRequested;
        String failure;
        Entry(String fingerprint, String operationId, String host, int port, String protocol, String request) {
            this.fingerprint = fingerprint; this.operationId = operationId; this.host = host;
            this.port = port; this.protocol = protocol;
            String[] firstLine = request.split("\\r?\\n", 2)[0].split("\\s+", 3);
            this.method = firstLine[0];
            this.path = firstLine.length > 1 ? firstLine[1].split("\\?", 2)[0] : "";
        }
    }

    @Override public synchronized void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        callbacks.setExtensionName("MCP Cancelable Scan Bridge");
        try {
            ManagementFactory.getPlatformMBeanServer().registerMBean(this, new ObjectName(OBJECT_NAME));
            loaded = true;
            callbacks.registerExtensionStateListener(this);
            callbacks.printOutput("Cancelable scan bridge ready: " + bridgeId + "; no scans started.");
        } catch (Exception error) {
            callbacks.printError("Bridge registration failed (an existing bridge is never replaced): " + error.getClass().getSimpleName());
            throw new IllegalStateException("Legacy scan bridge registration failed", error);
        }
    }

    @Override public synchronized void extensionUnloaded() {
        // Do not cancel, delete, or resume anything when unloading. Handles become unavailable.
        if (!loaded) return;
        loaded = false;
        try { ManagementFactory.getPlatformMBeanServer().unregisterMBean(new ObjectName(OBJECT_NAME)); }
        catch (Exception ignored) { }
    }

    private Map<String, Object> result(boolean success, String status) {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("success", success); value.put("status", status);
        value.put("bridgeId", bridgeId); value.put("backend", "LEGACY_QUEUE");
        return value;
    }

    private Map<String, Object> error(String code) {
        Map<String, Object> value = result(false, "ERROR"); value.put("errorCode", code); return value;
    }

    private static String text(Map<?, ?> args, String key) {
        Object value = args.get(key); return value instanceof String ? (String) value : "";
    }

    private static String state(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT).replaceFirst("\\.$", "");
    }
    private static boolean finished(String state) { return Set.of("done", "finished", "complete", "completed").contains(state); }
    private static boolean cancelled(String state) { return Set.of("cancelled", "canceled").contains(state); }

    private Map<String, Object> snapshot(Entry entry) {
        Map<String, Object> out = result(true, "OBSERVED");
        out.put("auditId", entry.id); out.put("startedAt", entry.createdAt);
        out.put("operationId", entry.operationId); out.put("host", entry.host); out.put("port", entry.port);
        out.put("protocol", entry.protocol); out.put("method", entry.method); out.put("path", entry.path);
        out.put("cancelRequested", entry.cancelRequested);
        out.put("cancelConfirmed", false); out.put("completed", null);
        out.put("remainingSeconds", null); // Cancellation is never a successful ETA of zero.
        if (entry.item == null) {
            out.put("success", false);
            out.put("status", entry.failure == null ? "STARTING" : "START_OUTCOME_UNKNOWN");
            out.put("errorCode", "START_OUTCOME_UNKNOWN");
            return out;
        }
        try {
            String raw = entry.item.getStatus(), normalized = state(raw);
            boolean confirmed = cancelled(normalized), complete = finished(normalized);
            out.put("auditStatusMessage", raw);
            out.put("cancelConfirmed", confirmed);
            out.put("completed", complete ? Boolean.TRUE : (confirmed || Set.of("scanning", "auditing", "running", "paused", "queued", "waiting", "starting").contains(normalized) ? Boolean.FALSE : null));
            out.put("status", confirmed ? "CANCELLED" : complete ? "FINISHED" : entry.cancelRequested ? "CANCEL_REQUESTED" : "OBSERVED");
            out.put("auditRequestCount", entry.item.getNumRequests());
            out.put("auditErrorCount", entry.item.getNumErrors());
            out.put("auditInsertionPointCount", entry.item.getNumInsertionPoints());
            // Read results without deleting the task. Unsupported result access is explicit.
            try { IScanIssue[] issues = entry.item.getIssues(); out.put("auditIssueCount", issues == null ? null : issues.length); }
            catch (RuntimeException unavailable) { out.put("auditIssueCount", null); }
        } catch (RuntimeException unavailable) {
            out.put("success", false); out.put("status", "STATE_UNAVAILABLE");
            out.put("errorCode", "STATE_UNAVAILABLE");
        }
        return out;
    }

    public synchronized Map<String, Object> execute(Map<?, ?> args) {
        if (!loaded) return error("BRIDGE_UNLOADED");
        String action = text(args, "action");
        if (action.equals("capabilities")) {
            Map<String, Object> out = result(true, "READY");
            out.put("protocolVersion", 1); out.put("trackedScans", entries.size());
            out.put("maxTrackedScans", MAX_ENTRIES); out.put("pauseSupported", false);
            out.put("existingMontoyaAuditsSupported", false);
            return out;
        }
        if (!bridgeId.equals(text(args, "bridgeId"))) return error("BRIDGE_MISMATCH");
        if (action.equals("start")) return start(args);
        if (action.equals("status") && text(args, "auditId").isEmpty()) {
            Map<String, Object> out = result(true, "OBSERVED");
            List<Map<String, Object>> scans = new ArrayList<>();
            entries.values().forEach(entry -> scans.add(snapshot(entry))); out.put("audits", scans); return out;
        }
        if (!Set.of("status", "cancel").contains(action)) return error("UNSUPPORTED_ACTION");
        Entry entry = entries.get(text(args, "auditId"));
        if (entry == null) return error("AUDIT_NOT_TRACKED");
        if (action.equals("status")) return snapshot(entry);
        Map<String, Object> before = snapshot(entry);
        if (!Boolean.TRUE.equals(before.get("success"))) return before;
        if (Boolean.TRUE.equals(before.get("cancelConfirmed"))) { before.put("status", "ALREADY_CANCELLED"); return before; }
        if (Boolean.TRUE.equals(before.get("completed"))) { before.put("status", "ALREADY_FINISHED"); return before; }
        if (entry.item == null) return error("START_OUTCOME_UNKNOWN");
        if (entry.cancelRequested) return before;
        entry.cancelRequested = true;
        try {
            entry.item.cancel();
            return snapshot(entry); // Only the observed status can confirm cancellation.
        } catch (RuntimeException failure) {
            Map<String, Object> out = snapshot(entry);
            out.put("success", false); out.put("errorCode", "CANCEL_OUTCOME_UNKNOWN");
            return out; // Do not blindly retry a potentially accepted call.
        }
    }

    private Map<String, Object> start(Map<?, ?> args) {
        String operationId = text(args, "operationId"), host = text(args, "host"), request = text(args, "request");
        String protocol = text(args, "protocol").toLowerCase(Locale.ROOT);
        Object portValue = args.get("port");
        if (!operationId.matches("[A-Za-z0-9_.-]{1,128}") || host.isBlank() || host.contains("\r") || host.contains("\n") || request.isBlank()
            || !(portValue instanceof Number) || !Set.of("http", "https").contains(protocol)) return error("INVALID_ARGUMENT");
        int port = ((Number) portValue).intValue();
        if (port < 1 || port > 65535 || ((Number) portValue).doubleValue() != port) return error("INVALID_ARGUMENT");
        String fingerprint;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            fingerprint = HexFormat.of().formatHex(digest.digest((host + "\n" + port + "\n" + protocol + "\n" + request).getBytes(StandardCharsets.UTF_8)));
        } catch (Exception impossible) { throw new IllegalStateException(impossible); }
        String existing = operations.get(operationId);
        if (existing != null) {
            Entry entry = entries.get(existing);
            return entry.fingerprint.equals(fingerprint) ? snapshot(entry) : error("OPERATION_CONFLICT");
        }
        if (entries.size() >= MAX_ENTRIES) return error("TRACKING_CAPACITY_REACHED");
        Entry entry = new Entry(fingerprint, operationId, host, port, protocol, request);
        entries.put(entry.id, entry); operations.put(operationId, entry.id);
        try {
            entry.item = callbacks.doActiveScan(host, port, protocol.equals("https"), callbacks.getHelpers().stringToBytes(request));
            if (entry.item == null) entry.failure = "NO_HANDLE";
        } catch (RuntimeException failure) { entry.failure = "START_OUTCOME_UNKNOWN"; }
        return snapshot(entry);
    }

    @Override public Object invoke(String actionName, Object[] params, String[] signature) throws ReflectionException {
        if (!"execute".equals(actionName) || params == null || params.length != 1 || !(params[0] instanceof Map))
            throw new ReflectionException(new NoSuchMethodException(actionName));
        return execute((Map<?, ?>) params[0]);
    }
    @Override public Object getAttribute(String name) throws AttributeNotFoundException { throw new AttributeNotFoundException(name); }
    @Override public void setAttribute(Attribute value) throws AttributeNotFoundException { throw new AttributeNotFoundException(value.getName()); }
    @Override public AttributeList getAttributes(String[] names) { return new AttributeList(); }
    @Override public AttributeList setAttributes(AttributeList values) { return new AttributeList(); }
    @Override public MBeanInfo getMBeanInfo() {
        MBeanParameterInfo parameter = new MBeanParameterInfo("arguments", "java.util.Map", "Protocol v1 request");
        return new MBeanInfo(getClass().getName(), "In-process legacy scan bridge", null, null,
            new MBeanOperationInfo[]{new MBeanOperationInfo("execute", "Execute a scoped scan operation", new MBeanParameterInfo[]{parameter}, "java.util.Map", MBeanOperationInfo.ACTION_INFO)}, null);
    }
}
