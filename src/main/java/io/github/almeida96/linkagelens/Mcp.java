package io.github.almeida96.linkagelens;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** A stdio MCP session bound to one report loaded by the operator. */
public final class Mcp {
    private static final ObjectMapper JSON = Main.JSON;
    private static final String LATEST = "2025-11-25";
    private static final int MAX_FRAME = 1024 * 1024;
    private static final int PAGE_LIMIT = 100;
    private static final List<String> TOOLS = List.of("linkage_summary", "list_findings", "list_duplicates", "inspect_duplicate");
    private final JsonNode report;
    private final Map<Integer, JsonNode> artifacts = new HashMap<>();
    private final Map<String, JsonNode> duplicates = new HashMap<>();
    private boolean negotiated;
    private boolean ready;

    private Mcp(JsonNode report) {
        if (report == null || !report.path("formatVersion").isInt() || report.get("formatVersion").intValue() != 1
                || !Set.of("PASS", "WARN", "FAIL").contains(report.path("status").asText(""))
                || !report.path("targetRelease").isInt() || !report.path("artifacts").isArray()
                || !report.path("duplicates").isArray() || !report.path("findings").isArray()) {
            throw invalid("Expected a LinkageLens version 1 report");
        }
        for (JsonNode artifact : report.get("artifacts")) {
            JsonNode index = artifact.path("index");
            if (!index.isInt() || !artifact.path("name").isTextual() || !artifact.path("sha256").isTextual()
                    || artifacts.putIfAbsent(index.intValue(), artifact) != null) {
                throw invalid("Invalid or repeated artifact index in report");
            }
        }
        for (JsonNode duplicate : report.get("duplicates")) {
            String className = string(duplicate, "className");
            if (!duplicate.path("identical").isBoolean() || !duplicate.path("providers").isArray()
                    || duplicate.get("providers").size() < 2 || duplicates.putIfAbsent(className, duplicate) != null) {
                throw invalid("Invalid duplicate definition in report");
            }
            for (JsonNode provider : duplicate.get("providers")) {
                if (!provider.path("artifact").isInt() || !artifacts.containsKey(provider.get("artifact").intValue())
                        || !provider.path("entry").isTextual() || !provider.path("sha256").isTextual()) {
                    throw invalid("Invalid class provider in report");
                }
            }
        }
        this.report = report;
    }

    public static void serve(JsonNode report, InputStream input, OutputStream output) throws IOException {
        var session = new Mcp(report);
        var stream = new BufferedInputStream(input);
        byte[] frame = new byte[MAX_FRAME];
        int used = 0;
        boolean oversized = false;
        int next;
        while ((next = stream.read()) != -1) {
            if (next == '\n') {
                session.respond(frame, used, oversized, output);
                used = 0;
                oversized = false;
            } else if (used < MAX_FRAME) {
                frame[used++] = (byte) next;
            } else {
                oversized = true;
            }
        }
        if (used != 0 || oversized) session.respond(frame, used, oversized, output);
    }

    private void respond(byte[] frame, int used, boolean oversized, OutputStream output) throws IOException {
        ObjectNode reply;
        if (oversized) {
            reply = error(null, -32700, "Message exceeds 1 MiB");
        } else {
            try {
                String text = StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(frame, 0, used)).toString();
                JsonNode request = JSON.readTree(text);
                reply = request == null || request.isMissingNode()
                        ? error(null, -32700, "Empty JSON message") : handle(request);
            } catch (JsonProcessingException | CharacterCodingException invalid) {
                reply = error(null, -32700, "Invalid UTF-8 JSON message");
            }
        }
        if (reply == null) return;
        byte[] bytes = JSON.writeValueAsBytes(reply);
        if (bytes.length > MAX_FRAME) {
            bytes = JSON.writeValueAsBytes(error(reply.get("id"), -32603, "Result exceeds 1 MiB. Request a smaller page."));
        }
        output.write(bytes);
        output.write('\n');
        output.flush();
    }

    private ObjectNode handle(JsonNode request) {
        JsonNode id = request.get("id");
        if (!request.isObject() || !"2.0".equals(request.path("jsonrpc").textValue())
                || !request.path("method").isTextual()
                || (id != null && !(id.isIntegralNumber() || id.isTextual()))
                || (id != null && id.toString().length() > 1024)) {
            return error(null, -32600, "Invalid JSON-RPC request");
        }
        String method = request.path("method").textValue();
        if (id == null) {
            if ("notifications/initialized".equals(method) && negotiated) ready = true;
            return null;
        }
        JsonNode params = request.has("params") ? request.get("params") : JSON.createObjectNode();
        if (!params.isObject()) return error(id, -32602, "params must be an object");
        try {
            if ("ping".equals(method)) return success(id, JSON.createObjectNode());
            if ("initialize".equals(method)) {
                if (negotiated) return error(id, -32600, "Session already initialized");
                String version = string(params, "protocolVersion");
                if (!params.path("capabilities").isObject()) throw invalid("Missing client capabilities");
                string(params.path("clientInfo"), "name");
                string(params.path("clientInfo"), "version");
                ObjectNode result = JSON.createObjectNode();
                result.put("protocolVersion", "2025-06-18".equals(version) ? version : LATEST);
                result.putObject("serverInfo").put("name", "linkagelens").put("version", Main.VERSION);
                result.putObject("capabilities").putObject("tools").put("listChanged", false);
                negotiated = true;
                return success(id, result);
            }
            if (!ready) return error(id, -32600, "Complete initialization first");
            if ("tools/list".equals(method)) {
                fields(params, Set.of("_meta"));
                return success(id, inventory());
            }
            if (!"tools/call".equals(method)) return error(id, -32601, "Method not found");
            fields(params, Set.of("name", "arguments", "_meta"));
            JsonNode args = params.has("arguments") ? params.get("arguments") : JSON.createObjectNode();
            if (!args.isObject()) throw invalid("arguments must be an object");
            String name = string(params, "name");
            if (!TOOLS.contains(name)) return error(id, -32602, "Unknown tool");
            ObjectNode data;
            try {
                data = call(name, args);
            } catch (IllegalArgumentException e) {
                ObjectNode failure = JSON.createObjectNode().put("isError", true);
                failure.putArray("content").addObject().put("type", "text").put("text", e.getMessage());
                return success(id, failure);
            }
            ObjectNode result = JSON.createObjectNode().put("isError", false);
            result.set("structuredContent", data);
            result.putArray("content").addObject().put("type", "text").put("text", data.toString());
            return success(id, result);
        } catch (IllegalArgumentException e) {
            return error(id, -32602, e.getMessage());
        }
    }

    private ObjectNode call(String name, JsonNode args) {
        ObjectNode result = JSON.createObjectNode();
        if ("linkage_summary".equals(name)) {
            fields(args, Set.of());
            copyFields(report, result, "formatVersion", "status", "targetRelease", "stats");
            return result.put("artifactCount", artifacts.size()).put("duplicateCount", duplicates.size())
                    .put("findingCount", report.get("findings").size());
        }
        boolean findings = "list_findings".equals(name);
        boolean inspecting = "inspect_duplicate".equals(name);
        if (inspecting) fields(args, Set.of("className", "limit", "offset"));
        else if (findings) fields(args, Set.of("owner", "limit", "offset"));
        else fields(args, Set.of("limit", "offset"));
        int offset = integer(args, "offset", 0, 0, Integer.MAX_VALUE);
        int limit = integer(args, "limit", 25, 1, PAGE_LIMIT);
        if (inspecting) {
            String className = string(args, "className");
            JsonNode duplicate = duplicates.get(className);
            if (duplicate == null) throw invalid("No duplicate definition for this class");
            copyFields(duplicate, result, "className", "identical");
            JsonNode providers = duplicate.get("providers");
            result.set("selectedArtifact", providers.get(0).get("artifact"));
            int start = Math.min(offset, providers.size());
            int end = start + Math.min(limit, providers.size() - start);
            ArrayNode page = result.putArray("providers");
            for (int i = start; i < end; i++) {
                JsonNode provider = providers.get(i);
                ObjectNode item = page.addObject();
                copyFields(provider, item, "artifact", "entry", "sha256");
                JsonNode artifact = artifacts.get(provider.get("artifact").intValue());
                item.set("artifactName", artifact.get("name"));
                item.set("artifactSha256", artifact.get("sha256"));
                item.put("selected", i == 0);
            }
            return pagination(result, offset, page.size(), providers.size());
        }
        String key = findings ? "findings" : "duplicates";
        String owner = args.has("owner") ? string(args, "owner") : null;
        JsonNode records = report.get(key);
        ArrayNode page = result.putArray(key);
        int total = 0;
        for (JsonNode row : records) {
            if (owner != null && !owner.equals(row.path("owner").textValue())) continue;
            if (total++ < offset || page.size() == limit) continue;
            if (findings) {
                page.add(row);
            } else {
                ObjectNode item = page.addObject();
                copyFields(row, item, "className", "identical");
                item.put("providerCount", row.get("providers").size());
                item.set("selectedArtifact", row.get("providers").get(0).get("artifact"));
            }
        }
        return pagination(result, offset, page.size(), total);
    }

    private static ObjectNode pagination(ObjectNode result, int offset, int count, int total) {
        result.put("offset", offset).put("total", total);
        if (offset < total - count) result.put("nextOffset", offset + count);
        else result.putNull("nextOffset");
        return result;
    }

    private static ObjectNode inventory() {
        ObjectNode result = JSON.createObjectNode();
        ArrayNode list = result.putArray("tools");
        for (String name : TOOLS) {
            ObjectNode tool = list.addObject().put("name", name);
            tool.put("description", switch (name) {
                case "linkage_summary" -> "Read the scan verdict, target Java release, counts and available analysis statistics.";
                case "list_findings" -> "Page through bytecode linkage findings with their caller and target evidence. Optionally filter by the exact target owner in dotted binary form.";
                case "list_duplicates" -> "List duplicate binary class names, selected artifact indices, provider counts and whether class bytes match.";
                default -> "Read the selected artifact index and page through all JARs providing a duplicate class in classpath order. Each provider includes the archive name, archive digest, entry and class digest.";
            });
            tool.putObject("annotations").put("readOnlyHint", true).put("destructiveHint", false)
                    .put("idempotentHint", true).put("openWorldHint", false);
            tool.putObject("outputSchema").put("type", "object");
            ObjectNode schema = tool.putObject("inputSchema").put("type", "object").put("additionalProperties", false);
            ObjectNode properties = schema.putObject("properties");
            if ("linkage_summary".equals(name)) continue;
            properties.putObject("offset").put("type", "integer").put("minimum", 0).put("maximum", Integer.MAX_VALUE);
            properties.putObject("limit").put("type", "integer").put("minimum", 1).put("maximum", PAGE_LIMIT);
            if ("inspect_duplicate".equals(name)) {
                properties.putObject("className").put("type", "string").put("minLength", 1);
                schema.putArray("required").add("className");
            }
            if ("list_findings".equals(name)) properties.putObject("owner").put("type", "string").put("minLength", 1);
        }
        return result;
    }

    private static void copyFields(JsonNode source, ObjectNode destination, String... keys) {
        for (String key : keys) if (source.has(key)) destination.set(key, source.get(key));
    }

    private static String string(JsonNode params, String key) {
        JsonNode value = params.path(key);
        if (!value.isTextual() || value.textValue().isEmpty()) throw invalid("Expected a nonempty string for " + key);
        return value.textValue();
    }

    private static int integer(JsonNode node, String key, int fallback, int min, int max) {
        if (!node.has(key)) return fallback;
        JsonNode value = node.get(key);
        if (!value.isIntegralNumber() || !value.canConvertToInt() || value.intValue() < min || value.intValue() > max)
            throw invalid(key + " must be an integer between " + min + " and " + max);
        return value.intValue();
    }

    private static void fields(JsonNode node, Set<String> allowed) {
        node.fieldNames().forEachRemaining(key -> {
            if (!allowed.contains(key)) throw invalid("Unexpected parameter");
        });
    }

    private static IllegalArgumentException invalid(String message) { return new IllegalArgumentException(message); }

    private static ObjectNode envelope(JsonNode id) {
        ObjectNode reply = JSON.createObjectNode().put("jsonrpc", "2.0");
        return reply.set("id", id);
    }

    private static ObjectNode success(JsonNode id, ObjectNode data) {
        return envelope(id).set("result", data);
    }

    private static ObjectNode error(JsonNode id, int code, String message) {
        ObjectNode reply = envelope(id);
        reply.putObject("error").put("code", code).put("message", message);
        return reply;
    }
}
