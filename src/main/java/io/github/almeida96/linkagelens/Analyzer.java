package io.github.almeida96.linkagelens;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.almeida96.linkagelens.JarIndex.Definition;
import io.github.almeida96.linkagelens.JarIndex.Member;
import io.github.almeida96.linkagelens.JarIndex.Use;
import org.objectweb.asm.Opcodes;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

final class Analyzer {
    private static final JsonNodeFactory JSON = JsonNodeFactory.instance;
    private static final int MAX_LOOKUP_STEPS = 4_000_000;
    private static final int MAX_FINDINGS = 20_000;

    // Object is the only platform ancestor for which we model methods. These names
    // also cover non-public implementation methods on supported OpenJDK releases.
    // A name match alone conservatively suppresses a missing-member diagnosis.
    private static final Set<String> OBJECT_METHODS = Set.of("getClass", "hashCode", "equals",
            "clone", "toString", "notify", "notifyAll", "wait", "wait0", "finalize", "registerNatives");

    private record Signature(boolean method, String name, String descriptor) {}
    private record Reference(String owner, Signature signature, int opcode, boolean interfaceOwner) {}
    private record Result(String code, int alternative, String detail) {}
    private static final Result COMPATIBLE = new Result("", -1, "");
    private static final Result UNKNOWN = new Result("", -1, "inconclusive");
    private enum Lookup { ABSENT, DECLARED, UNKNOWN }

    private final Map<String, List<Definition>> classes;
    private final Map<Definition, Map<Signature, Member>> memberTables = new IdentityHashMap<>();
    private final Map<Reference, Result> resolutions = new HashMap<>();
    private final Set<String> shadows = new HashSet<>();
    private final int maxMajor;
    private int steps;

    private Analyzer(JarIndex index, int targetRelease) {
        classes = new TreeMap<>(index.definitions());
        maxMajor = 44 + targetRelease;
    }

    static ObjectNode analyze(JarIndex index, int targetRelease) {
        return new Analyzer(index, targetRelease).report(index, targetRelease);
    }

    private ObjectNode report(JarIndex index, int targetRelease) {
        ObjectNode report = JSON.objectNode().put("formatVersion", 1).put("targetRelease", targetRelease);
        ArrayNode artifacts = report.putArray("artifacts");
        for (var artifact : index.artifacts()) {
            artifacts.addObject().put("index", artifact.index()).put("name", artifact.name())
                    .put("sha256", artifact.sha256());
        }

        ArrayNode duplicates = report.putArray("duplicates");
        for (var entry : classes.entrySet()) {
            List<Definition> providers = entry.getValue();
            if (providers.size() < 2) continue;
            String winnerHash = providers.getFirst().sha256();
            boolean identical = providers.stream().allMatch(d -> d.sha256().equals(winnerHash));
            if (!identical) shadows.add(entry.getKey());
            ArrayNode listed = duplicates.addObject().put("className", binary(entry.getKey()))
                    .put("identical", identical).putArray("providers");
            for (Definition provider : providers) {
                listed.addObject().put("artifact", provider.artifact()).put("entry", provider.entry())
                        .put("sha256", provider.sha256());
            }
        }

        int instructions = 0, inconclusive = 0;
        ArrayNode findings = report.putArray("findings");
        Map<String, ObjectNode> locations = new HashMap<>();
        for (List<Definition> providers : classes.values()) {
            Definition caller = providers.getFirst();
            for (Use use : caller.uses()) {
                instructions++;
                if (!shadows.contains(use.owner())) continue;
                if (caller.major() > maxMajor || platform(caller.name())) {
                    inconclusive++;
                    continue;
                }
                Signature signature = new Signature(use.method(), use.name(), use.descriptor());
                var reference = new Reference(use.owner(), signature, use.opcode(), use.interfaceOwner());
                Result result = resolutions.computeIfAbsent(reference, this::resolve);
                if (result == UNKNOWN) inconclusive++;
                if (result.code().isEmpty()) continue;
                String id = locationId(caller, use, result);
                ObjectNode finding = locations.get(id);
                if (finding != null) {
                    finding.put("occurrences", finding.path("occurrences").intValue() + 1);
                } else {
                    if (locations.size() >= MAX_FINDINGS)
                        throw new IllegalArgumentException("More than " + MAX_FINDINGS + " distinct linkage findings");
                    finding = findings.addObject().put("id", id).put("code", result.code())
                            .put("caller", binary(caller.name())).put("callerArtifact", caller.artifact())
                            .put("callerMethod", use.callerMethod()).put("callerDescriptor", use.callerDescriptor())
                            .put("line", use.line()).put("opcode", opcodeName(use.opcode()))
                            .put("referenceKind", !use.method() ? "Fieldref" : use.interfaceOwner() ? "InterfaceMethodref" : "Methodref")
                            .put("owner", binary(use.owner())).put("member", use.name())
                            .put("descriptor", use.descriptor()).put("selectedArtifact", classes.get(use.owner()).getFirst().artifact())
                            .put("alternativeArtifact", result.alternative()).put("occurrences", 1).put("detail", result.detail());
                    locations.put(id, finding);
                }
            }
        }
        report.putObject("stats").put("selectedClasses", classes.size()).put("directInstructions", instructions)
                .put("differingClasses", shadows.size()).put("inconclusiveReferences", inconclusive);
        report.put("status", !findings.isEmpty() ? "FAIL" : shadows.isEmpty() ? "PASS" : "WARN");
        return report;
    }

    private Result resolve(Reference ref) {
        List<Definition> providers = classes.get(ref.owner());
        Definition winner = providers.getFirst();
        Signature sig = ref.signature();
        boolean constructor = sig.method() && sig.name().equals("<init>");
        if (platform(ref.owner()) || winner.major() > maxMajor || !flag(winner.access(), Opcodes.ACC_PUBLIC)
                || ref.opcode() == Opcodes.INVOKESPECIAL && !constructor
                || constructor && (ref.opcode() != Opcodes.INVOKESPECIAL || ref.interfaceOwner())
                || ref.opcode() == Opcodes.INVOKEINTERFACE && !ref.interfaceOwner()
                || ref.opcode() == Opcodes.INVOKEVIRTUAL && ref.interfaceOwner()) return UNKNOWN;
        boolean itf = flag(winner.access(), Opcodes.ACC_INTERFACE);
        // A method's constant-pool entry encodes its owner kind even for invokestatic.
        // Fields use a single Fieldref tag for both class and interface owners.
        boolean wrongOwnerKind = sig.method() && ref.interfaceOwner() != itf;
        boolean wantsStatic = ref.opcode() == Opcodes.INVOKESTATIC || ref.opcode() == Opcodes.GETSTATIC
                || ref.opcode() == Opcodes.PUTSTATIC;
        Member direct = member(winner, sig);
        if (!wrongOwnerKind && direct != null) {
            if (!flag(direct.access(), Opcodes.ACC_PUBLIC)) return UNKNOWN;
            if (flag(direct.access(), Opcodes.ACC_STATIC) == wantsStatic) return COMPATIBLE;
        }

        // A concrete alternative makes the finding actionable. Restrict evidence to
        // a public declaration on that duplicate class, with the opcode's staticness.
        Definition alternative = null;
        for (int i = 1; i < providers.size(); i++) {
            if (++steps > MAX_LOOKUP_STEPS) return UNKNOWN;
            Definition other = providers.get(i);
            if (other.sha256().equals(winner.sha256()) || other.major() > maxMajor
                    || !flag(other.access(), Opcodes.ACC_PUBLIC)
                    || sig.method() && ref.interfaceOwner() != flag(other.access(), Opcodes.ACC_INTERFACE)) continue;
            Member m = member(other, sig);
            if (m != null && flag(m.access(), Opcodes.ACC_PUBLIC) && flag(m.access(), Opcodes.ACC_STATIC) == wantsStatic) {
                alternative = other;
                break;
            }
        }
        if (alternative == null) return COMPATIBLE;
        if (wrongOwnerKind) {
            return new Result("OWNER_KIND_MISMATCH", alternative.artifact(),
                    "The " + opcodeName(ref.opcode()) + " instruction references " + (ref.interfaceOwner() ? "an interface" : "a class")
                            + " method. The selected owner is " + (itf ? "an interface" : "a class")
                            + " and the later provider has the expected declaration.");
        }
        if (direct != null) {
            return new Result("STATIC_MISMATCH", alternative.artifact(),
                    "The selected class declares an " + (wantsStatic ? "instance member" : "incompatible static member")
                    + ". The instruction expects " + (wantsStatic ? "a static" : "an instance")
                    + " member. The later provider has the expected declaration.");
        }

        // Constructors must be declared by the symbolic owner. Other member
        // references can remain valid through an ancestor or a superinterface.
        if (!constructor) {
            Lookup inherited = inherited(winner, sig);
            if (inherited == Lookup.DECLARED) return COMPATIBLE;
            if (inherited == Lookup.UNKNOWN) return UNKNOWN;
        }
        return new Result(sig.method() ? "MISSING_METHOD" : "MISSING_FIELD", alternative.artifact(),
                constructor ? "The selected class lacks this constructor descriptor. A later provider declares it."
                            : "The member is absent from the selected class and its examined hierarchy. A later provider declares it.");
    }

    private Lookup inherited(Definition winner, Signature sig) {
        var queue = new ArrayDeque<String>();
        enqueueAncestors(winner, queue);
        var seen = new HashSet<String>();
        boolean incomplete = false;
        while (!queue.isEmpty()) {
            if (++steps > MAX_LOOKUP_STEPS || seen.size() >= 1024) return Lookup.UNKNOWN;
            String name = queue.removeFirst();
            if (!seen.add(name)) continue;
            if (name.equals("java/lang/Object")) {
                if (sig.method() && OBJECT_METHODS.contains(sig.name())) return Lookup.UNKNOWN;
                continue;
            }
            List<Definition> providers = classes.get(name);
            if (platform(name) || providers == null || providers.getFirst().major() > maxMajor || name.equals(winner.name())) {
                incomplete = true;
                continue;
            }
            Definition ancestor = providers.getFirst();
            Member m = member(ancestor, sig);
            // Static and private interface methods are not inherited (JVMS 5.4.3).
            if (m != null && !(sig.method() && flag(ancestor.access(), Opcodes.ACC_INTERFACE)
                    && (flag(m.access(), Opcodes.ACC_STATIC) || flag(m.access(), Opcodes.ACC_PRIVATE)))) {
                return Lookup.DECLARED;
            }
            enqueueAncestors(ancestor, queue);
        }
        return incomplete ? Lookup.UNKNOWN : Lookup.ABSENT;
    }

    private static void enqueueAncestors(Definition d, ArrayDeque<String> queue) {
        if (d.parent() != null) queue.add(d.parent());
        queue.addAll(d.interfaces());
    }

    private Member member(Definition def, Signature sig) {
        Map<Signature, Member> members = memberTables.computeIfAbsent(def, d -> {
            Map<Signature, Member> map = new HashMap<>();
            for (Member m : d.members()) map.put(new Signature(m.method(), m.name(), m.descriptor()), m);
            return map;
        });
        return members.get(sig);
    }

    private static boolean platform(String name) {
        return name.startsWith("java/") || name.startsWith("javax/") || name.startsWith("jdk/")
                || name.startsWith("sun/") || name.startsWith("com/sun/") || name.startsWith("org/w3c/")
                || name.startsWith("org/xml/sax/") || name.startsWith("org/ietf/jgss/") || name.startsWith("netscape/javascript/");
    }

    private static boolean flag(int access, int flag) { return (access & flag) != 0; }
    private static String binary(String internal) { return internal.replace('/', '.'); }

    private static String locationId(Definition caller, Use use, Result result) {
        ArrayNode key = JSON.arrayNode().add(result.code()).add(caller.name()).add(use.callerMethod())
                .add(use.callerDescriptor()).add(use.line()).add(use.opcode()).add(use.owner()).add(use.name()).add(use.descriptor());
        if (use.interfaceOwner()) key.add("InterfaceMethodref");
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(key.toString().getBytes(StandardCharsets.UTF_8));
            return "LL-" + HexFormat.of().formatHex(digest, 0, 12);
        } catch (NoSuchAlgorithmException impossible) {
            throw new AssertionError(impossible);
        }
    }

    private static String opcodeName(int opcode) {
        return switch (opcode) {
            case Opcodes.INVOKEVIRTUAL -> "invokevirtual";
            case Opcodes.INVOKESTATIC -> "invokestatic";
            case Opcodes.INVOKESPECIAL -> "invokespecial";
            case Opcodes.INVOKEINTERFACE -> "invokeinterface";
            case Opcodes.GETFIELD -> "getfield";
            case Opcodes.PUTFIELD -> "putfield";
            case Opcodes.GETSTATIC -> "getstatic";
            case Opcodes.PUTSTATIC -> "putstatic";
            default -> throw new IllegalArgumentException("Unsupported instruction " + opcode);
        };
    }
}
