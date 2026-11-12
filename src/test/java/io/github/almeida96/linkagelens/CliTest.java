package io.github.almeida96.linkagelens;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class CliTest {
    @TempDir Path work;

    private int run(String... args) {
        try (var out = new PrintStream(new ByteArrayOutputStream())) {
            return Main.execute(args, new ByteArrayInputStream(new byte[0]), out, out);
        }
    }

    @Test void listsRelativeToTheInputFileCanContainSpacesAndAUtf8Bom() throws Exception {
        Path folder = Files.createDirectory(work.resolve("jars"));
        Path jar = folder.resolve("library file.jar");
        try (var input = Main.class.getResourceAsStream("/checkout/tariff-current.jar")) {
            assertNotNull(input);
            Files.copy(input, jar);
        }
        var list = Files.writeString(folder.resolve("cp.txt"), "\uFEFFlibrary file.jar\r\n\r\n");
        var dest = work.resolve("report");
        assertEquals(0, run("scan", "--classpath-file", list.toString(), "--target", "8", "--out", dest.toString()));
        var report = Main.JSON.readTree(Files.readAllBytes(dest.resolve("report.json")));
        assertEquals("library file.jar", report.at("/artifacts/0/name").asText());
        assertEquals(8, report.get("targetRelease").intValue());
        String html = Files.readString(dest.resolve("report.html"));
        assertTrue(html.contains("No shadowed linkage conflict found"));
        assertTrue(html.contains("href=\"report.json\""));
        assertFalse(html.contains(work.toString()));
    }

    @Test void invalidInputsLeaveNoPartialReport() throws Exception {
        var missing = work.resolve("missing.jar").toString();
        var out = work.resolve("result");
        assertEquals(2, run("scan", "--jar", missing, "--out", out.toString()));
        assertFalse(Files.exists(out));
        assertEquals(2, run("scan", "--jar", missing, "--classpath-file", "also.txt", "--out", out.toString()));
        assertEquals(2, run("scan", "--jar", missing, "--target", "22", "--out", out.toString()));
        assertEquals(2, run("scan", "--out", out.toString()));
        try (var files = Files.list(work)) { assertEquals(0, files.count()); }
    }
}
