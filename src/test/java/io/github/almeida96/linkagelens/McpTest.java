package io.github.almeida96.linkagelens;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

class McpTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String INITIALIZED = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}";
    private static final String REPORT = """
            {"formatVersion":1,"targetRelease":21,"status":"FAIL",
             "artifacts":[{"index":1,"name":"earlier.jar","sha256":"aaaa"},
                          {"index":2,"name":"later.jar","sha256":"bbbb"}],
             "duplicates":[{"className":"demo.Service","identical":false,"providers":[
                 {"artifact":1,"entry":"demo/Service.class","sha256":"1111"},
                 {"artifact":2,"entry":"META-INF/versions/21/demo/Service.class","sha256":"2222"}]}],
             "findings":[{"id":"a","code":"MISSING","caller":"client.Main","owner":"demo.Other"},
                         {"id":"b","code":"MISSING","caller":"client.Main","owner":"demo.Service"}],
             "stats":{"classesScanned":8}}
            """;

    private static String request(String method, ObjectNode params) {
        return JSON.createObjectNode().put("jsonrpc", "2.0").put("id", "request").put("method", method)
                .set("params", params).toString();
    }

    private static String init(String version) {
        ObjectNode params = JSON.createObjectNode().put("protocolVersion", version);
        params.putObject("clientInfo").put("name", "test").put("version", "1");
        params.putObject("capabilities");
        return request("initialize", params);
    }

    private static String call(String tool, String args) throws Exception {
        ObjectNode params = JSON.createObjectNode().put("name", tool);
        params.set("arguments", JSON.readTree(args));
        return request("tools/call", params);
    }

    private static List<JsonNode> exchange(JsonNode report, byte[] frames) throws Exception {
        var out = new ByteArrayOutputStream();
        Mcp.serve(report, new ByteArrayInputStream(frames), out);
        var messages = new ArrayList<JsonNode>();
        for (String frame : out.toString(UTF_8).lines().toList()) messages.add(JSON.readTree(frame));
        return messages;
    }

    private static List<JsonNode> session(JsonNode report, String... frames) throws Exception {
        String batch = init("2025-11-25") + "\n" + INITIALIZED + "\n" + String.join("\n", frames) + "\n";
        var messages = exchange(report, batch.getBytes(UTF_8));
        assertEquals("2025-11-25", messages.removeFirst().at("/result/protocolVersion").asText());
        return messages;
    }

    @Test void negotiatesVersionAndWaitsForClientReadiness() throws Exception {
        String inventory = request("tools/list", JSON.createObjectNode());
        var frames = List.of(inventory, init("2025-06-18"), inventory, INITIALIZED,
                "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\"}", inventory, init("2025-06-18"));
        var messages = exchange(JSON.readTree(REPORT), String.join("\r\n", frames).getBytes(UTF_8));
        assertEquals(5, messages.size());
        assertEquals(-32600, messages.get(0).at("/error/code").asInt());
        assertEquals("2025-06-18", messages.get(1).at("/result/protocolVersion").asText());
        assertEquals(-32600, messages.get(2).at("/error/code").asInt());
        var tools = messages.get(3).at("/result/tools");
        List<String> names = new ArrayList<>();
        tools.forEach(tool -> {
            names.add(tool.path("name").asText());
            assertTrue(tool.at("/annotations/readOnlyHint").booleanValue());
            assertFalse(tool.at("/annotations/openWorldHint").booleanValue());
        });
        assertEquals(List.of("linkage_summary", "list_findings", "list_duplicates", "inspect_duplicate"), names);
        assertEquals(-32600, messages.get(4).at("/error/code").asInt());
        var fallback = exchange(JSON.readTree(REPORT), init("future").getBytes(UTF_8));
        assertEquals("2025-11-25", fallback.getFirst().at("/result/protocolVersion").asText());
    }

    @Test void pagesFindingsWithExactOwnerFilterAndPreservesEvidence() throws Exception {
        JsonNode report = JSON.readTree(REPORT);
        var replies = session(report, call("linkage_summary", "{}"),
                call("list_findings", "{\"limit\":1}"), call("list_findings", "{\"offset\":1}"),
                call("list_findings", "{\"owner\":\"demo.Service\"}"),
                call("list_findings", "{\"offset\":2147483647}"));
        JsonNode summary = data(replies.get(0));
        assertEquals("FAIL", summary.path("status").asText());
        assertEquals(2, summary.path("artifactCount").asInt());
        assertEquals(2, summary.path("findingCount").asInt());
        assertEquals(1, summary.path("duplicateCount").asInt());
        assertEquals(8, summary.at("/stats/classesScanned").asInt());
        assertEquals(1, data(replies.get(1)).path("nextOffset").intValue());
        assertEquals(report.at("/findings/0"), data(replies.get(1)).at("/findings/0"));
        assertTrue(data(replies.get(2)).path("nextOffset").isNull());
        assertEquals("b", data(replies.get(2)).at("/findings/0/id").asText());
        assertEquals(1, data(replies.get(3)).path("total").intValue());
        assertEquals(report.at("/findings/1"), data(replies.get(3)).at("/findings/0"));
        assertTrue(data(replies.get(4)).path("findings").isEmpty());
    }

    @Test void linksDuplicateProvidersToJarsAndRetainsSelectionOnLaterPages() throws Exception {
        var replies = session(JSON.readTree(REPORT), call("list_duplicates", "{}"),
                call("inspect_duplicate", "{\"className\":\"demo.Service\",\"limit\":1}"),
                call("inspect_duplicate", "{\"className\":\"demo.Service\",\"offset\":1}"));
        JsonNode row = data(replies.getFirst()).at("/duplicates/0");
        assertEquals("demo.Service", row.path("className").textValue());
        assertEquals(2, row.path("providerCount").intValue());
        assertFalse(row.path("identical").asBoolean());
        assertEquals(1, row.path("selectedArtifact").intValue());
        JsonNode firstPage = data(replies.get(1));
        assertTrue(firstPage.at("/providers/0/selected").booleanValue());
        assertEquals("earlier.jar", firstPage.at("/providers/0/artifactName").textValue());
        assertEquals(1, firstPage.path("nextOffset").intValue());
        JsonNode secondPage = data(replies.get(2));
        assertEquals(1, secondPage.path("selectedArtifact").intValue());
        assertFalse(secondPage.at("/providers/0/selected").booleanValue());
        assertEquals("bbbb", secondPage.at("/providers/0/artifactSha256").textValue());
        assertEquals("2222", secondPage.at("/providers/0/sha256").textValue());
        assertTrue(secondPage.path("nextOffset").isNull());
        assertEquals(secondPage, JSON.readTree(replies.get(2).at("/result/content/0/text").asText()));
    }

    private static JsonNode data(JsonNode message) {
        assertFalse(message.at("/result/isError").asBoolean(), message::toString);
        return message.at("/result/structuredContent");
    }

    @Test void rejectsUnknownOrInvalidInputAndDoesNotChangeTheLoadedReport() throws Exception {
        JsonNode report = JSON.readTree(REPORT);
        var replies = session(report, call("run_jar", "{}"), request("artifacts/load", JSON.createObjectNode()),
                call("linkage_summary", "{\"path\":\"other.json\"}"),
                call("list_findings", "{\"limit\":0}"), call("list_duplicates", "{\"limit\":101}"),
                call("list_duplicates", "{\"offset\":2147483648}"), call("list_findings", "{\"offset\":1.5}"),
                call("list_findings", "{\"owner\":null}"), call("inspect_duplicate", "{\"className\":\"demo.service\"}"),
                request("ping", JSON.createObjectNode()));
        assertEquals(-32602, replies.get(0).at("/error/code").asInt());
        assertEquals(-32601, replies.get(1).at("/error/code").asInt());
        for (JsonNode reply : replies.subList(2, replies.size() - 1)) {
            assertTrue(reply.at("/result/isError").booleanValue());
        }
        assertEquals(JSON.createObjectNode(), replies.getLast().get("result"));
        assertEquals(JSON.readTree(REPORT), report);
    }

    @Test void validatesReportVersionAndProviderReferencesBeforeServing() throws Exception {
        ObjectNode report = (ObjectNode) JSON.readTree(REPORT);
        assertThrows(IllegalArgumentException.class, () -> exchange(report.put("formatVersion", "1"), new byte[0]));
        report.put("formatVersion", 1);
        ((ObjectNode) report.at("/duplicates/0/providers/0")).put("artifact", 0);
        assertThrows(IllegalArgumentException.class, () -> exchange(report, new byte[0]));
    }

    @Test void rejectsMalformedAndOversizedFramesThenResynchronizes() throws Exception {
        var input = new ByteArrayOutputStream();
        input.write((" ".repeat(1024 * 1024 + 1) + "\n").getBytes(UTF_8));
        input.write(new byte[] {(byte) 0xc3, 10});
        input.write("{}{}\n{\"jsonrpc\":\"1\",\"jsonrpc\":\"2\"}\n".getBytes(UTF_8));
        input.write(request("ping", JSON.createObjectNode()).getBytes(UTF_8));
        var messages = exchange(JSON.readTree(REPORT), input.toByteArray());
        assertEquals(5, messages.size());
        for (JsonNode message : messages.subList(0, 4)) {
            assertEquals(-32700, message.at("/error/code").intValue());
            assertTrue(message.get("id").isNull());
        }
        assertEquals("request", messages.getLast().path("id").textValue());
    }
}
