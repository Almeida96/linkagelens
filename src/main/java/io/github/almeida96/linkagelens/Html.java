package io.github.almeida96.linkagelens;

import com.fasterxml.jackson.databind.JsonNode;

final class Html {
    private static final int DISPLAY_LIMIT = 100;
    private Html() {}

    static String render(JsonNode report) {
        String status = report.path("status").asText();
        var artifacts = report.path("artifacts");
        var findings = report.path("findings");
        var duplicates = report.path("duplicates");
        StringBuilder html = new StringBuilder("""
                <!doctype html><html lang="en"><head><meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>Classpath report · LinkageLens</title>
                <style>
                :root{color-scheme:light;--ink:#24283c;--mute:#53586b;--line:#d9d9de;--paper:#f5f4f0}
                *{box-sizing:border-box}body{margin:0;border-top:5px solid #414384;background:var(--paper);color:var(--ink);font:16px/1.55 "Inter",system-ui,sans-serif}
                main{max-width:68rem;margin:auto;padding:0 clamp(1rem,5vw,3.25rem) 3rem}
                nav,header,section{border-bottom:1px solid var(--line)}nav{display:flex;align-items:center;gap:1rem;padding:1.15rem 0}
                nav strong{font-size:1.35rem;letter-spacing:-.055em}nav a{margin-left:auto}a{color:#393880;text-underline-offset:.22em}
                header{padding:2.2rem 0 1.5rem}h1{font:550 clamp(2rem,5vw,3.7rem)/1.1 Georgia,serif;letter-spacing:-.045em;margin:.65rem 0}
                h2{font-size:1.35rem;letter-spacing:-.03em;margin:0 0 .65rem}h3{font-size:1rem;margin:0}
                p{margin:.3rem 0}.status{display:inline-block;font-weight:750;font-size:.78rem;letter-spacing:.08em;border-radius:.25rem;padding:.14rem .6rem}
                .fail{color:#8a2b10;background:#ffe1ce}.warn{color:#694716;background:#f4e4b7}.pass{color:#145a40;background:#d6eee3}
                .meta{color:var(--mute);font-variant-numeric:tabular-nums}section{padding:1.4rem 0}
                article{margin:.8rem 0;padding:1rem 1.2rem;background:white;border:1px solid var(--line);border-left:4px solid #925432}
                dl{display:grid;grid-template-columns:minmax(7rem,25%) minmax(0,1fr);margin:.7rem 0 0;gap:.42rem 1rem}dt{color:var(--mute)}dd{margin:0}
                code,pre{font: .91em/1.5 "IBM Plex Mono",ui-monospace,monospace}code,a,dd,p,summary{overflow-wrap:anywhere}
                summary{cursor:pointer;padding:.4rem 0}details+details{border-top:1px solid var(--line)}
                ol{padding-left:1.65rem}li{padding:.25rem 0}.digest{color:var(--mute);font-size:.82rem;overflow-wrap:anywhere}
                @media(max-width:540px){dl{grid-template-columns:1fr;gap:0}dd{margin:0 0 .6rem}header{padding-top:1.3rem}}
                </style></head><body><main><nav aria-label="Report"><strong>LinkageLens</strong><a href="report.json">JSON evidence</a></nav>
                """);
        String headline = switch (status) {
            case "FAIL" -> "A shadowed class breaks a bytecode reference";
            case "WARN" -> "Different JARs supply different class definitions";
            default -> "No shadowed linkage conflict found";
        };
        html.append("<header><span class=\"status ").append(status.toLowerCase(java.util.Locale.ROOT)).append("\">")
                .append(status).append("</span><h1>").append(headline).append("</h1><p class=\"meta\">Java ")
                .append(report.path("targetRelease").asInt()).append(" · ").append(count(artifacts.size(), "JAR", "JARs"))
                .append(" · ").append(count(duplicates.size(), "duplicate class", "duplicate classes"))
                .append(" · ").append(count(findings.size(), "finding", "findings")).append("</p></header>");

        if (!findings.isEmpty()) {
            html.append("<section><h2>Conflicting references</h2>");
            for (int i = 0; i < Math.min(DISPLAY_LIMIT, findings.size()); i++) {
                var finding = findings.get(i);
                html.append("<article><h3><code>").append(esc(finding.path("owner").asText())).append('.')
                        .append(esc(finding.path("member").asText())).append("</code></h3><p>")
                        .append(esc(finding.path("detail").asText())).append("</p><dl>");
                field(html, "Instruction in", finding.path("caller").asText() + "." + finding.path("callerMethod").asText()
                        + finding.path("callerDescriptor").asText() + (finding.path("line").asInt(-1) > 0 ? " · line " + finding.get("line").asInt() : ""));
                field(html, "JVM descriptor", finding.path("descriptor").asText());
                field(html, "Selected JAR", provider(artifacts, finding.path("selectedArtifact").intValue()));
                if (finding.has("alternativeArtifact")) field(html, "Alternate JAR", provider(artifacts, finding.get("alternativeArtifact").intValue()));
                field(html, "Finding", finding.path("code").asText() + " · " + finding.path("id").asText());
                html.append("</dl></article>");
            }
            limit(html, findings.size());
            html.append("</section>");
        }
        html.append("<section><h2>Classpath order</h2><p>The first JAR containing a class supplies its definition.</p><ol>");
        for (var jar : artifacts) {
            html.append("<li><code>").append(esc(jar.path("name").asText())).append("</code><div class=\"digest\">")
                    .append(esc(jar.path("sha256").asText())).append("</div></li>");
        }
        html.append("</ol></section>");
        if (!duplicates.isEmpty()) {
            html.append("<section><h2>Duplicate definitions</h2>");
            for (int i = 0; i < Math.min(DISPLAY_LIMIT, duplicates.size()); i++) {
                var dup = duplicates.get(i);
                html.append("<details><summary><code>").append(esc(dup.path("className").asText()))
                        .append("</code> · ").append(dup.path("identical").asBoolean() ? "identical bytes" : "different bytes")
                        .append("</summary><ol>");
                for (var item : dup.path("providers")) html.append("<li><code>")
                        .append(esc(provider(artifacts, item.path("artifact").intValue()))).append("!")
                        .append(esc(item.path("entry").asText())).append("</code><div class=\"digest\">")
                        .append(esc(item.path("sha256").asText())).append("</div></li>");
                html.append("</ol></details>");
            }
            limit(html, duplicates.size());
            html.append("</section>");
        }
        if (report.path("stats").path("inconclusiveReferences").asLong() > 0) {
            html.append("<p>Inconclusive references: ").append(report.path("stats").path("inconclusiveReferences").asLong()).append(".</p>");
        }
        return html.append("</main></body></html>").toString();
    }

    private static void field(StringBuilder out, String label, String text) {
        out.append("<dt>").append(label).append("</dt><dd><code>").append(esc(text)).append("</code></dd>");
    }

    private static String provider(JsonNode artifacts, int index) {
        return "#" + (index + 1) + " " + artifacts.path(index).path("name").asText();
    }

    private static void limit(StringBuilder out, int total) {
        if (total > DISPLAY_LIMIT) out.append("<p>Showing the first ").append(DISPLAY_LIMIT).append(" of ")
                .append(total).append(". <a href=\"report.json\">Open the full JSON report.</a></p>");
    }

    private static String count(int value, String one, String many) {
        return value + " " + (value == 1 ? one : many);
    }

    private static String esc(String text) {
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
}
