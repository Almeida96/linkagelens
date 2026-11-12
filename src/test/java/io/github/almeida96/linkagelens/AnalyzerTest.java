package io.github.almeida96.linkagelens;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.almeida96.linkagelens.JarIndex.Artifact;
import io.github.almeida96.linkagelens.JarIndex.Definition;
import io.github.almeida96.linkagelens.JarIndex.Member;
import io.github.almeida96.linkagelens.JarIndex.Use;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.objectweb.asm.Opcodes.*;

class AnalyzerTest {
    static final String OBJECT = "java/lang/Object";
    static final int PUBLIC = ACC_PUBLIC, STATIC = ACC_PUBLIC | ACC_STATIC;
    static final String API = "pricing/Tariff";
    static final Member RATE = new Member(true, "rate", "(I)I", STATIC);
    static final Member FEE = new Member(false, "fee", "J", PUBLIC);

    static Definition def(int artifact, String name, String parent, int access, List<String> interfaces,
                          List<Member> members, List<Use> uses) {
        return new Definition(artifact, name + ".class", "fixture" + artifact, 65,
                name, parent, interfaces, access, members, uses);
    }

    static Definition api(int artifact, Member... members) {
        return def(artifact, API, OBJECT, PUBLIC, List.of(), List.of(members), List.of());
    }

    static Use use(int line, int opcode, Member m) {
        return new Use("total", "()J", line, opcode, API, m.name(), m.descriptor(), m.method(), opcode == INVOKEINTERFACE);
    }

    static ObjectNode analyze(List<Use> calls, Definition... providers) {
        Map<String, List<Definition>> classes = new LinkedHashMap<>();
        ArrayList<Artifact> artifacts = new ArrayList<>();
        artifacts.add(new Artifact(0, "client.jar", "client"));
        var caller = def(0, "app/Checkout", OBJECT, PUBLIC, List.of(), List.of(), calls);
        classes.put(caller.name(), List.of(caller));
        for (Definition provider : providers) {
            artifacts.add(new Artifact(provider.artifact(), provider.artifact() + ".jar", "test"));
            classes.computeIfAbsent(provider.name(), k -> new ArrayList<>()).add(provider);
        }
        return Analyzer.analyze(new JarIndex(artifacts, classes), 21);
    }

    @Test void recordsTheSelectedProviderAndCallerForBothFieldsAndMethods() {
        var report = analyze(List.of(use(7, INVOKESTATIC, RATE), use(7, INVOKESTATIC, RATE), use(8, GETFIELD, FEE)),
                api(1), api(2, RATE, FEE));
        assertEquals("FAIL", report.path("status").asText());
        assertEquals(2, report.path("findings").size());
        var method = report.at("/findings/0");
        assertEquals("MISSING_METHOD", method.path("code").asText());
        assertEquals("app.Checkout", method.path("caller").asText());
        assertEquals("pricing.Tariff", method.path("owner").asText());
        assertEquals(7, method.path("line").asInt());
        assertEquals(2, method.path("occurrences").asInt());
        assertEquals(1, method.path("selectedArtifact").asInt());
        assertEquals(2, method.path("alternativeArtifact").asInt());
        assertEquals("MISSING_FIELD", report.at("/findings/1/code").asText());
        var reordered = analyze(List.of(use(7, INVOKESTATIC, RATE), use(8, GETFIELD, FEE)), api(2, RATE, FEE), api(1));
        assertEquals("WARN", reordered.path("status").asText());
        assertTrue(reordered.path("findings").isEmpty());
    }

    @Test void requiresAPublicAlternativeWithTheExpectedInvocationMode() {
        Member instance = new Member(true, RATE.name(), RATE.descriptor(), PUBLIC);
        Member privateStatic = new Member(true, RATE.name(), RATE.descriptor(), ACC_PRIVATE | ACC_STATIC);
        var fail = analyze(List.of(use(9, INVOKESTATIC, RATE)), api(1, instance), api(2, RATE));
        assertEquals("STATIC_MISMATCH", fail.at("/findings/0/code").asText());
        var unknown = analyze(List.of(use(9, INVOKESTATIC, RATE)), api(1, instance), api(2, privateStatic));
        assertTrue(unknown.path("findings").isEmpty());
        var wrongAlternative = analyze(List.of(use(9, INVOKESTATIC, RATE)), api(1), api(2, instance));
        assertTrue(wrongAlternative.path("findings").isEmpty());
    }

    @Test void keepsInheritedMembersAndUnknownParentsOutOfConfirmedFindings() {
        var derived = def(1, API, "shared/Base", PUBLIC, List.of("shared/Fees"), List.of(), List.of());
        var parent = def(3, "shared/Base", OBJECT, PUBLIC, List.of(), List.of(RATE), List.of());
        var itf = def(4, "shared/Fees", OBJECT, PUBLIC | ACC_INTERFACE, List.of(),
                List.of(new Member(true, "label", "()I", PUBLIC)), List.of());
        var label = new Member(true, "label", "()I", PUBLIC);
        var calls = List.of(use(2, INVOKESTATIC, RATE), use(9, INVOKEVIRTUAL, label));
        var valid = analyze(calls, derived, api(2, RATE, label), parent, itf);
        assertEquals("WARN", valid.path("status").asText());
        assertTrue(valid.path("findings").isEmpty());
        var unknown = analyze(calls, derived, api(2, RATE, label), itf);
        assertTrue(unknown.path("findings").isEmpty());
        assertEquals(1, unknown.at("/stats/inconclusiveReferences").asInt());
    }

    @Test void constructorsAreNotInheritedAndDescriptorsAreExact() {
        var ctor = new Member(true, "<init>", "(I)V", PUBLIC);
        var selected = def(1, API, "missing/Base", PUBLIC, List.of(),
                List.of(new Member(true, "<init>", "()V", PUBLIC)), List.of());
        var report = analyze(List.of(use(-1, INVOKESPECIAL, ctor)), selected, api(2, ctor));
        assertEquals("MISSING_METHOD", report.at("/findings/0/code").asText());
        assertEquals(-1, report.at("/findings/0/line").asInt());
        var otherDescriptor = new Member(true, "rate", "(J)I", STATIC);
        var overload = analyze(List.of(use(8, INVOKESTATIC, RATE)), api(1, otherDescriptor), api(2, RATE));
        assertEquals("MISSING_METHOD", overload.at("/findings/0/code").asText());
    }

    @Test void ignoresIdenticalDefinitionsAndBytecodeFromTheLosingCopy() {
        var identical = analyze(List.of(use(1, INVOKESTATIC, RATE)), api(1), api(1));
        assertEquals("PASS", identical.path("status").asText());
        assertTrue(identical.at("/duplicates/0/identical").asBoolean());
        var first = def(3, "app/Plugin", OBJECT, PUBLIC, List.of(), List.of(), List.of());
        var inactive = def(4, "app/Plugin", OBJECT, PUBLIC, List.of(), List.of(), List.of(use(2, INVOKESTATIC, RATE)));
        var report = analyze(List.of(), api(1), api(2, RATE), first, inactive);
        assertEquals("WARN", report.path("status").asText());
        assertTrue(report.path("findings").isEmpty());
    }

    @Test void distinguishesAnInterfaceReferenceEvenWhenTheMemberDescriptorMatches() {
        var price = new Member(true, "price", "()I", PUBLIC);
        var selected = api(1, price);
        var alternative = def(2, API, OBJECT, PUBLIC | ACC_INTERFACE, List.of(), List.of(price), List.of());
        var report = analyze(List.of(use(3, INVOKEINTERFACE, price)), selected, alternative);
        assertEquals("OWNER_KIND_MISMATCH", report.at("/findings/0/code").asText());
        assertEquals(2, report.at("/findings/0/alternativeArtifact").asInt());
    }

    @Test void knownObjectMethodsAreHandledConservativelyOnInterfaces() {
        var stringMethod = new Member(true, "toString", "()Ljava/lang/String;", PUBLIC);
        var base = def(1, API, OBJECT, PUBLIC | ACC_INTERFACE, List.of(), List.of(), List.of());
        var alt = def(2, API, OBJECT, PUBLIC | ACC_INTERFACE, List.of(), List.of(stringMethod), List.of());
        var report = analyze(List.of(use(1, INVOKEINTERFACE, stringMethod)), base, alt);
        assertEquals("WARN", report.path("status").asText());
        assertTrue(report.path("findings").isEmpty());
    }

    @Test void separatesStaticInterfaceAndClassReferencesSharingTheSameOpcodeAndDescriptor() {
        var classOwner = api(1, RATE);
        var interfaceOwner = def(2, API, OBJECT, PUBLIC | ACC_INTERFACE, List.of(), List.of(RATE), List.of());
        var callClass = use(12, INVOKESTATIC, RATE);
        var callInterface = new Use("total", "()J", 12, INVOKESTATIC, API, RATE.name(), RATE.descriptor(), true, true);
        for (boolean classFirst : List.of(true, false)) {
            var report = analyze(List.of(callClass, callInterface),
                    classFirst ? classOwner : interfaceOwner, classFirst ? interfaceOwner : classOwner);
            assertEquals(1, report.path("findings").size());
            var finding = report.at("/findings/0");
            assertEquals("OWNER_KIND_MISMATCH", finding.path("code").asText());
            assertEquals(classFirst ? "InterfaceMethodref" : "Methodref", finding.path("referenceKind").asText());
            assertEquals(classFirst ? 2 : 1, finding.path("alternativeArtifact").asInt());
            assertEquals(1, finding.path("occurrences").asInt());
        }
    }

    @Test void staticFieldsUseTheSameConstantPoolKindForClassAndInterfaceOwners() {
        var value = new Member(false, "value", "I", STATIC);
        var alt = def(2, API, OBJECT, PUBLIC | ACC_INTERFACE, List.of(), List.of(value), List.of());
        var report = analyze(List.of(use(1, GETSTATIC, value)), api(1), alt);
        assertEquals("MISSING_FIELD", report.at("/findings/0/code").asText());
        assertEquals("Fieldref", report.at("/findings/0/referenceKind").asText());
        var valid = analyze(List.of(use(1, GETSTATIC, value)), api(1, value), alt);
        assertTrue(valid.path("findings").isEmpty());
    }
}
