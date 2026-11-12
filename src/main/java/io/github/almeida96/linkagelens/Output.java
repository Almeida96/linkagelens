package io.github.almeida96.linkagelens;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.core.util.DefaultIndenter;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Comparator;

final class Output {
    static final int REPORT_LIMIT = 32 * 1024 * 1024;
    private Output() {}

    interface Writer<T> { T write(Path folder) throws IOException; }

    static <T> T publish(Path dest, Writer<T> writer) throws IOException {
        Path path = dest.toAbsolutePath().normalize();
        if (path.getParent() == null || Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Choose a new output directory: " + path);
        }
        Files.createDirectories(path.getParent());
        Path staging = Files.createTempDirectory(path.getParent(), ".linkagelens-");
        try {
            T result = writer.write(staging);
            Files.move(staging, path);
            return result;
        } finally {
            if (Files.exists(staging)) {
                try (var files = Files.walk(staging)) {
                    for (Path file : files.sorted(Comparator.reverseOrder()).toList()) Files.delete(file);
                }
            }
        }
    }

    static void report(Path dest, JsonNode report) throws IOException {
        var indenter = new DefaultIndenter("  ", "\n");
        var format = new DefaultPrettyPrinter().withObjectIndenter(indenter);
        byte[] json = Main.JSON.writer(format).writeValueAsBytes(report);
        if (json.length > REPORT_LIMIT) throw new IOException("Report exceeds 32 MiB");
        Files.write(dest.resolve("report.json"), json);
        Files.writeString(dest.resolve("report.html"), Html.render(report));
    }
}
