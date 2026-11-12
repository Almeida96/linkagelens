package io.github.almeida96.linkagelens;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Selected class definitions from an explicit, ordered application classpath. */
record JarIndex(List<Artifact> artifacts, Map<String, List<Definition>> definitions) {
    record Artifact(int index, String name, String sha256) {}
    record Definition(int artifact, String entry, String sha256, int major, String name, String parent,
                      List<String> interfaces, int access, List<Member> members, List<Use> uses) {}
    record Member(boolean method, String name, String descriptor, int access) {}
    record Use(String callerMethod, String callerDescriptor, int line, int opcode, String owner,
               String name, String descriptor, boolean method, boolean interfaceOwner) {}

    private record Selected(ZipEntry entry, int release) {}

    private static final String VERSIONS = "META-INF/versions/";
    private static final int MIB = 1024 * 1024;
    private static final int MAX_JARS = 256;
    private static final long MAX_JAR_BYTES = 256L * MIB;
    private static final long MAX_INPUT_BYTES = 1024L * MIB;
    private static final int MAX_ENTRIES = 250_000;
    private static final int MAX_CLASS_BYTES = 4 * MIB;
    private static final long MAX_SELECTED_BYTES = 256L * MIB;
    private static final int MAX_MEMBERS_AND_USES = 1_000_000;
    private static final int MAX_MANIFEST_BYTES = MIB;

    static JarIndex read(List<Path> orderedJars, int targetRelease) throws IOException {
        if (targetRelease < 8 || targetRelease > 21) throw new IOException("Target release must be 8 through 21");
        if (orderedJars.isEmpty() || orderedJars.size() > MAX_JARS) throw new IOException("Supply 1 to 256 JAR files");
        var artifacts = new ArrayList<Artifact>();
        var definitions = new TreeMap<String, List<Definition>>();
        var budget = new Budget();
        for (Path file : orderedJars) {
            if (!Files.isRegularFile(file)) throw new IOException("Expected a regular JAR file: " + file);
            String displayName = file.getFileName().toString();
            Path snapshot = Files.createTempFile("linkagelens-", ".jar");
            try {
                // Index the very bytes that received the artifact digest, even if the original path is replaced.
                String digest = copyAndHash(file, snapshot, budget);
                Artifact artifact = new Artifact(artifacts.size(), displayName, digest);
                try (ZipFile archive = new ZipFile(snapshot.toFile())) {
                    scan(archive, artifact.index(), targetRelease, definitions, budget);
                }
                artifacts.add(artifact);
            } catch (IOException | IllegalArgumentException e) {
                throw new IOException("Cannot index " + displayName + ": " + e.getMessage(), e);
            } finally {
                Files.deleteIfExists(snapshot);
            }
        }
        definitions.replaceAll((name, values) -> List.copyOf(values));
        return new JarIndex(List.copyOf(artifacts), Collections.unmodifiableMap(definitions));
    }

    private static String copyAndHash(Path input, Path copy, Budget budget) throws IOException {
        if (Files.size(input) > MAX_JAR_BYTES) throw new IOException("JAR exceeds 256 MiB");
        MessageDigest digest = sha256();
        try (var in = Files.newInputStream(input); var out = Files.newOutputStream(copy)) {
            byte[] buffer = new byte[64 * 1024];
            long size = 0;
            int read;
            while ((read = in.read(buffer)) != -1) {
                size += read;
                budget.sourceBytes += read;
                if (size > MAX_JAR_BYTES || budget.sourceBytes > MAX_INPUT_BYTES) {
                    throw new IOException("JAR input exceeds 256 MiB per file or 1 GiB per scan");
                }
                digest.update(buffer, 0, read);
                out.write(buffer, 0, read);
            }
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private static void scan(ZipFile archive, int artifact, int target, Map<String, List<Definition>> definitions,
                             Budget budget) throws IOException {
        if (archive.size() > MAX_ENTRIES - budget.entries) throw new IOException("Classpath exceeds 250,000 archive entries");
        budget.entries += archive.size();
        var names = new HashSet<String>();
        ZipEntry manifest = null;
        for (var entries = archive.entries(); entries.hasMoreElements();) {
            ZipEntry entry = entries.nextElement();
            if (!names.add(entry.getName())) throw new IOException("Duplicate archive entry: " + entry.getName());
            if ("META-INF/MANIFEST.MF".equalsIgnoreCase(entry.getName())) {
                if (manifest != null) throw new IOException("Multiple manifest entries");
                manifest = entry;
            }
        }
        boolean multiRelease = false;
        if (manifest != null) {
            byte[] bytes = readEntry(archive, manifest, MAX_MANIFEST_BYTES);
            var attrs = new Manifest(new ByteArrayInputStream(bytes)).getMainAttributes();
            multiRelease = "true".equalsIgnoreCase(attrs.getValue(Attributes.Name.MULTI_RELEASE));
        }
        var selected = new TreeMap<String, Selected>();
        for (var entries = archive.entries(); entries.hasMoreElements();) {
            ZipEntry entry = entries.nextElement();
            if (!entry.isDirectory() && entry.getName().endsWith(".class")) {
                select(selected, entry, multiRelease, target);
            }
        }
        for (var item : selected.entrySet()) {
            ZipEntry entry = item.getValue().entry();
            int allowed = (int) Math.min(MAX_CLASS_BYTES, MAX_SELECTED_BYTES - budget.selectedBytes);
            byte[] bytes = readEntry(archive, entry, allowed);
            budget.selectedBytes += bytes.length;
            Definition definition = parse(bytes, artifact, entry.getName(), item.getKey(), budget);
            definitions.computeIfAbsent(definition.name(), ignored -> new ArrayList<>()).add(definition);
        }
    }

    private static void select(Map<String, Selected> selected, ZipEntry entry, boolean multiRelease, int target)
            throws IOException {
        String path = entry.getName();
        int release = 0;
        if (path.startsWith(VERSIONS)) {
            if (!multiRelease) return;
            int end = path.indexOf('/', VERSIONS.length());
            if (end < 0) return;
            String digits = path.substring(VERSIONS.length(), end);
            // Accepted targets are 8..21. Leading zeroes and signed version directories are ignored by the JDK.
            if (digits.isEmpty() || digits.length() > 2 || digits.charAt(0) == '0'
                    || !digits.chars().allMatch(c -> c >= '0' && c <= '9')) return;
            release = Integer.parseInt(digits);
            // JDK 21 may load entries from versions/8 on a later release, contrary to the JAR specification.
            if (release == 8 && target > 8) throw new IOException("Ambiguous multi-release layout: " + entry.getName());
            if (release < 9 || release > target) return;
            path = path.substring(end + 1);
        }
        if (path.startsWith("META-INF/") || path.equals("module-info.class")) return;
        String name = path.substring(0, path.length() - ".class".length());
        Selected current = selected.get(name);
        if (current == null || current.release() < release) selected.put(name, new Selected(entry, release));
    }

    private static byte[] readEntry(ZipFile archive, ZipEntry entry, int limit) throws IOException {
        if (entry.getSize() < 0 || entry.getSize() > limit) throw new IOException("Size limit exceeded: " + entry.getName());
        byte[] bytes;
        try (InputStream input = archive.getInputStream(entry)) {
            bytes = input.readNBytes((int) entry.getSize() + 1);
        }
        CRC32 crc = new CRC32();
        crc.update(bytes);
        if (bytes.length != entry.getSize() || crc.getValue() != entry.getCrc()) {
            throw new IOException("Archive entry size or CRC mismatch: " + entry.getName());
        }
        return bytes;
    }

    private static Definition parse(byte[] bytes, int artifact, String entry, String name, Budget budget)
            throws IOException {
        if (bytes.length < 10 || bytes[0] != (byte) 0xca || bytes[1] != (byte) 0xfe
                || bytes[2] != (byte) 0xba || bytes[3] != (byte) 0xbe) throw new IOException("Invalid class header: " + entry);
        try {
            var reader = new ClassReader(bytes);
            if (!name.equals(reader.getClassName())) {
                throw new IOException("Class " + reader.getClassName() + " does not match entry " + entry
                        + ". Use classpath-root JARs.");
            }
            var visitor = new Symbols(budget);
            reader.accept(visitor, ClassReader.SKIP_FRAMES);
            return new Definition(artifact, entry, HexFormat.of().formatHex(sha256().digest(bytes)),
                    reader.readUnsignedShort(6), name, reader.getSuperName(), List.of(reader.getInterfaces()),
                    reader.getAccess(), List.copyOf(visitor.members), List.copyOf(visitor.uses));
        } catch (RuntimeException e) {
            throw new IOException("Cannot read class " + entry + ": " + e.getMessage(), e);
        }
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException impossible) {
            throw new AssertionError(impossible);
        }
    }

    private static final class Budget {
        long sourceBytes;
        long selectedBytes;
        int entries;
        int symbols;

        void symbol() {
            if (++symbols > MAX_MEMBERS_AND_USES) throw new IllegalArgumentException("Classpath exceeds one million declarations and references");
        }
    }

    private static final class Symbols extends ClassVisitor {
        final Budget budget;
        final List<Member> members = new ArrayList<>();
        final List<Use> uses = new ArrayList<>();

        Symbols(Budget budget) {
            super(Opcodes.ASM9);
            this.budget = budget;
        }

        @Override public FieldVisitor visitField(int access, String name, String descriptor, String signature, Object value) {
            budget.symbol();
            members.add(new Member(false, name, descriptor, access));
            return null;
        }

        @Override public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
            budget.symbol();
            members.add(new Member(true, name, descriptor, access));
            return new MethodVisitor(Opcodes.ASM9) {
                int line = -1;

                @Override public void visitLineNumber(int number, Label start) {
                    line = number;
                }

                @Override public void visitFieldInsn(int opcode, String owner, String field, String type) {
                    budget.symbol();
                    uses.add(new Use(name, descriptor, line, opcode, owner, field, type, false, false));
                }

                @Override public void visitMethodInsn(int opcode, String owner, String method, String type, boolean isInterface) {
                    budget.symbol();
                    uses.add(new Use(name, descriptor, line, opcode, owner, method, type, true, isInterface));
                }
            };
        }
    }
}
