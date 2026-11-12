package io.github.almeida96.linkagelens;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class Main {
    static final String VERSION = "0.1.0";
    static final ObjectMapper JSON = new ObjectMapper(JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build())
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private static final String HELP = """
            LinkageLens — diagnose shadowed Java classes on an ordered JAR classpath

              linkagelens scan --out NEW_DIR [--target 8..21] [--strict] --jar FIRST.jar --jar NEXT.jar ...
              linkagelens scan --out NEW_DIR [--target 8..21] [--strict] --classpath-file paths.txt
              linkagelens demo --out NEW_DIR
              linkagelens mcp --report report.json
              linkagelens --version

            --target defaults to 21. Classpath files contain one path per line, relative to the file.
            scan exit codes: 0 accepted, 1 linkage finding or strict warning, 2 input or I/O error.
            """;

    private Main() {}

    public static void main(String[] args) {
        System.exit(execute(args, System.in, System.out, System.err));
    }

    static int execute(String[] args, InputStream in, PrintStream out, PrintStream err) {
        try {
            if (args.length == 0 || (args.length == 1 && List.of("--help", "-h", "help").contains(args[0]))) {
                out.print(HELP);
                return args.length == 0 ? 2 : 0;
            }
            if (Arrays.equals(args, new String[]{"--version"})) {
                out.println(VERSION);
                return 0;
            }
            switch (args[0]) {
                case "scan" -> {
                    Scan options = Scan.parse(args);
                    var paths = options.inputs();
                    var report = Output.publish(options.out, dir -> {
                        var result = analyze(paths, options.target);
                        Output.report(dir, result);
                        return result;
                    });
                    String verdict = report.path("status").asText();
                    out.printf("%s  %d findings, %d duplicate classes  %s%n", verdict, report.path("findings").size(),
                            report.path("duplicates").size(), options.out.resolve("report.html"));
                    return verdict.equals("FAIL") || (options.strict && verdict.equals("WARN")) ? 1 : 0;
                }
                case "demo" -> {
                    Path dir = onlyPath(args, "--out");
                    Output.publish(dir, Main::demo);
                    out.println("FAIL  " + dir.resolve("broken/report.html"));
                    out.println("WARN  " + dir.resolve("reordered/report.html"));
                    out.println("PASS  " + dir.resolve("fixed/report.html"));
                    return 0;
                }
                case "mcp" -> {
                    Path path = onlyPath(args, "--report");
                    JsonNode report = JSON.readTree(read(path, Output.REPORT_LIMIT));
                    Mcp.serve(report, in, out);
                    return 0;
                }
                default -> throw new IllegalArgumentException("Unknown command: " + args[0] + ". See --help");
            }
        } catch (Exception problem) {
            String detail = problem.getMessage();
            err.println("linkagelens: " + (detail == null ? problem.getClass().getSimpleName() : detail));
            return 2;
        }
    }

    private static Path onlyPath(String[] args, String flag) {
        if (args.length != 3 || !args[1].equals(flag) || args[2].isBlank())
            throw new IllegalArgumentException("Expected " + args[0] + " " + flag + " PATH");
        return Path.of(args[2]);
    }

    static ObjectNode analyze(List<Path> paths, int target) throws IOException {
        JarIndex index = JarIndex.read(paths, target);
        for (var providers : index.definitions().values()) {
            var first = providers.getFirst();
            if (first.major() > target + 44) {
                String jar = index.artifacts().get(first.artifact()).name();
                throw new IOException(jar + "!" + first.entry() + " uses class file version " + first.major()
                        + ", above the Java " + target + " limit of " + (target + 44));
            }
        }
        return Analyzer.analyze(index, target);
    }

    private static Void demo(Path dir) throws IOException {
        Path jars = Files.createDirectory(dir.resolve("jars"));
        for (String name : List.of("checkout.jar", "tariff-legacy.jar", "tariff-current.jar")) {
            try (var stream = Main.class.getResourceAsStream("/checkout/" + name)) {
                if (stream == null) throw new IOException("Missing bundled example: " + name);
                Files.copy(stream, jars.resolve(name));
            }
        }
        for (String scenario : List.of("broken", "reordered", "fixed")) {
            List<String> libs = switch (scenario) {
                case "broken" -> List.of("checkout.jar", "tariff-legacy.jar", "tariff-current.jar");
                case "reordered" -> List.of("checkout.jar", "tariff-current.jar", "tariff-legacy.jar");
                default -> List.of("checkout.jar", "tariff-current.jar");
            };
            var output = Files.createDirectory(dir.resolve(scenario));
            String entries = String.join("\n", libs.stream().map(n -> "../jars/" + n).toList());
            Files.writeString(output.resolve("classpath.txt"), entries + "\n", StandardCharsets.UTF_8);
            var report = analyze(libs.stream().map(jars::resolve).toList(), 21);
            String expected = switch (scenario) { case "broken" -> "FAIL"; case "reordered" -> "WARN"; default -> "PASS"; };
            if (!expected.equals(report.path("status").asText())) throw new IOException("Unexpected demo verdict for " + scenario);
            Output.report(output, report);
        }
        return null;
    }

    static byte[] read(Path file, int limit) throws IOException {
        if (!Files.isRegularFile(file)) throw new IOException("Expected a file: " + file);
        try (var stream = Files.newInputStream(file)) {
            byte[] bytes = stream.readNBytes(limit + 1);
            if (bytes.length > limit) throw new IOException("File exceeds " + limit + " bytes: " + file);
            return bytes;
        }
    }

    private static final class Scan {
        Path out;
        Path list;
        final List<Path> jars = new ArrayList<>();
        int target = 21;
        boolean strict;

        static Scan parse(String[] args) {
            var parsed = new Scan();
            var seen = new java.util.HashSet<String>();
            for (int i = 1; i < args.length; i++) {
                String flag = args[i];
                if (!flag.equals("--jar") && !seen.add(flag)) throw new IllegalArgumentException("Repeated option: " + flag);
                if (flag.equals("--strict")) { parsed.strict = true; continue; }
                if (!List.of("--out", "--target", "--jar", "--classpath-file").contains(flag))
                    throw new IllegalArgumentException("Unknown option: " + flag);
                if (++i >= args.length || args[i].isBlank() || args[i].startsWith("--"))
                    throw new IllegalArgumentException("Missing value for " + flag);
                String value = args[i];
                switch (flag) {
                    case "--out" -> parsed.out = Path.of(value);
                    case "--classpath-file" -> parsed.list = Path.of(value);
                    case "--jar" -> parsed.jars.add(Path.of(value));
                    case "--target" -> parsed.target = Integer.parseInt(value);
                }
            }
            if (parsed.out == null) throw new IllegalArgumentException("Missing --out");
            if ((parsed.list == null) == parsed.jars.isEmpty()) throw new IllegalArgumentException("Use --jar or --classpath-file");
            if (parsed.target < 8 || parsed.target > 21) throw new IllegalArgumentException("--target must be between 8 and 21");
            return parsed;
        }

        List<Path> inputs() throws IOException {
            if (list == null) return List.copyOf(jars);
            String lines = StandardCharsets.UTF_8.newDecoder()
                    .decode(java.nio.ByteBuffer.wrap(read(list, 1024 * 1024))).toString();
            if (lines.startsWith("\uFEFF")) lines = lines.substring(1);
            Path parent = list.toAbsolutePath().getParent();
            var files = lines.lines().filter(line -> !line.isBlank()).map(parent::resolve).toList();
            if (files.isEmpty()) throw new IOException("Empty classpath: " + list);
            return files;
        }
    }
}
