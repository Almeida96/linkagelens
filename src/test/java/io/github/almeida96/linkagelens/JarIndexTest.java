package io.github.almeida96.linkagelens;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.Opcodes;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class JarIndexTest {
    @TempDir Path root;

    private static byte[] definition(String name, int version, String tag) {
        var writer = new ClassWriter(0);
        writer.visit(version, Opcodes.ACC_PUBLIC, name, null, "java/lang/Object", new String[]{"java/io/Serializable"});
        writer.visitField(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, tag, "I", null, null).visitEnd();
        var method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", "()I", null, null);
        method.visitCode();
        Label start = new Label();
        method.visitLabel(start);
        method.visitLineNumber(19, start);
        method.visitFieldInsn(Opcodes.GETSTATIC, "sample/Api", "COUNT", "I");
        method.visitMethodInsn(Opcodes.INVOKESTATIC, "sample/Api", "normalize", "(I)I", false);
        method.visitMethodInsn(Opcodes.INVOKESTATIC, "sample/Normalizer", "apply", "(I)I", true);
        method.visitInsn(Opcodes.IRETURN);
        method.visitMaxs(1, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private Path zip(String name, Map<String, byte[]> entries) throws IOException {
        Path file = root.resolve(name);
        try (var archive = new ZipOutputStream(Files.newOutputStream(file))) {
            for (var entry : entries.entrySet()) {
                archive.putNextEntry(new ZipEntry(entry.getKey()));
                archive.write(entry.getValue());
                archive.closeEntry();
            }
        }
        return file;
    }

    private static byte[] manifest(String multiRelease) {
        return ("Manifest-Version: 1.0\r\nMulti-Release: " + multiRelease + "\r\n\r\n")
                .getBytes(StandardCharsets.UTF_8);
    }

    @Test void extractsDirectBytecodeUsesWithLineAndHashesWhileKeepingProviderOrder() throws Exception {
        byte[] current = definition("sample/Caller", Opcodes.V21, "CURRENT");
        Path early = zip("first #1.jar", Map.of("sample/Caller.class", current));
        Path late = zip("later.jar", Map.of("sample/Caller.class", definition("sample/Caller", Opcodes.V1_8, "EARLY")));
        var index = JarIndex.read(List.of(early, late), 21);
        assertEquals(List.of("first #1.jar", "later.jar"), index.artifacts().stream().map(JarIndex.Artifact::name).toList());
        assertEquals(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(early))),
                index.artifacts().getFirst().sha256());
        var providers = index.definitions().get("sample/Caller");
        assertEquals(List.of(0, 1), providers.stream().map(JarIndex.Definition::artifact).toList());
        var first = providers.getFirst();
        assertEquals(65, first.major());
        assertEquals("sample/Caller.class", first.entry());
        assertEquals("java/lang/Object", first.parent());
        assertEquals(List.of("java/io/Serializable"), first.interfaces());
        assertEquals(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(current)), first.sha256());
        assertNotEquals(first.sha256(), providers.getLast().sha256());
        assertEquals(List.of(new JarIndex.Use("run", "()I", 19, Opcodes.GETSTATIC, "sample/Api", "COUNT", "I", false, false),
                new JarIndex.Use("run", "()I", 19, Opcodes.INVOKESTATIC, "sample/Api", "normalize", "(I)I", true, false),
                new JarIndex.Use("run", "()I", 19, Opcodes.INVOKESTATIC, "sample/Normalizer", "apply", "(I)I", true, true)),
                first.uses());
        assertTrue(first.members().contains(new JarIndex.Member(false, "CURRENT", "I", Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC)));
        assertTrue(first.members().contains(new JarIndex.Member(true, "run", "()I", Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC)));
    }

    @Test void choosesTheSameMultiReleaseEntriesAsTheJdkWithoutExposingModuleMetadata() throws Exception {
        var entries = new LinkedHashMap<String, byte[]>();
        String name = "sample/Api.class";
        entries.put(name, definition("sample/Api", Opcodes.V1_8, "base"));
        entries.put("META-INF/versions/17/" + name, definition("sample/Api", Opcodes.V17, "v17"));
        entries.put("META-INF/versions/11/" + name, definition("sample/Api", Opcodes.V11, "v11"));
        entries.put("META-INF/versions/11/sample/Only.class", definition("sample/Only", Opcodes.V11, "only"));
        entries.put("META-INF/versions/021/" + name, new byte[]{1});
        entries.put("META-INF/versions/22/" + name, new byte[]{1});
        entries.put("module-info.class", new byte[]{1});
        entries.put("META-INF/versions/11/module-info.class", new byte[]{1});
        entries.put("META-INF/versions/17/META-INF/invalid.class", new byte[]{1});
        entries.put("META-INF/MANIFEST.MF", manifest("TrUe"));
        Path enabled = zip("multi.jar", entries);
        for (int version : List.of(8, 10, 11, 16, 17, 21)) {
            var index = JarIndex.read(List.of(enabled), version);
            try (var runtimeView = new JarFile(enabled.toFile(), false, JarFile.OPEN_READ, Runtime.Version.parse(Integer.toString(version)))) {
                assertEquals(runtimeView.getJarEntry(name).getRealName(), index.definitions().get("sample/Api").getFirst().entry());
                assertEquals(runtimeView.getJarEntry("sample/Only.class") != null, index.definitions().containsKey("sample/Only"));
                assertEquals(version < 11 ? 1 : 2, index.definitions().size());
            }
        }
        entries.put("META-INF/versions/8/" + name, new byte[]{1});
        Path ambiguous = zip("ambiguous.jar", entries);
        assertTrue(assertThrows(IOException.class, () -> JarIndex.read(List.of(ambiguous), 21))
                .getMessage().contains("Ambiguous multi-release layout"));
        entries.put("META-INF/MANIFEST.MF", manifest("false"));
        var plain = JarIndex.read(List.of(zip("ordinary.jar", entries)), 21);
        assertEquals(1, plain.definitions().size());
        assertEquals(name, plain.definitions().get("sample/Api").getFirst().entry());
    }

    @Test void refusesOverlappingPhysicalEntriesIncludingIdenticalBytes() throws Exception {
        Path jar = zip("duplicates.jar", Map.of("metadata-a", new byte[0], "metadata-b", new byte[0]));
        byte[] bytes = Files.readAllBytes(jar);
        byte[] search = "metadata-b".getBytes(StandardCharsets.US_ASCII);
        int edited = 0;
        for (int i = 0; i <= bytes.length - search.length; i++) {
            if (Arrays.equals(bytes, i, i + search.length, search, 0, search.length)) {
                bytes[i + search.length - 1] = 'a';
                edited++;
            }
        }
        assertEquals(2, edited);
        Files.write(jar, bytes);
        assertTrue(assertThrows(IOException.class, () -> JarIndex.read(List.of(jar), 21)).getMessage().contains("Duplicate archive entry"));
    }

    @Test void refusesBrokenClassesAndDisagreementBetweenClassNameAndEntryPath() throws Exception {
        Path bad = zip("bad.jar", Map.of("sample/One.class", new byte[12]));
        assertTrue(assertThrows(IOException.class, () -> JarIndex.read(List.of(bad), 21)).getMessage().contains("Invalid class header"));
        Path misplaced = zip("boot-layout.jar", Map.of("BOOT-INF/classes/sample/One.class",
                definition("sample/One", Opcodes.V21, "x")));
        assertTrue(assertThrows(IOException.class, () -> JarIndex.read(List.of(misplaced), 21)).getMessage().contains("does not match entry"));
        byte[] truncated = Arrays.copyOf(definition("sample/One", Opcodes.V21, "x"), 22);
        Path shortClass = zip("truncated.jar", Map.of("sample/One.class", truncated));
        assertThrows(IOException.class, () -> JarIndex.read(List.of(shortClass), 21));
    }

    @Test void boundsExpandedClassBytesAndSkipsTheBodiesOfUnrelatedResources() throws Exception {
        byte[] inflated = new byte[4 * 1024 * 1024 + 1];
        Path oversized = zip("large.jar", Map.of("sample/One.class", inflated));
        assertTrue(Files.size(oversized) < 8192);
        assertTrue(assertThrows(IOException.class, () -> JarIndex.read(List.of(oversized), 21)).getMessage().contains("Size limit"));
        Path resource = zip("resource.jar", Map.of("model.bin", inflated));
        assertTrue(JarIndex.read(List.of(resource), 21).definitions().isEmpty());
    }
}
