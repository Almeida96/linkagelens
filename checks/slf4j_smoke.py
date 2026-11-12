"""Reproduce a JVM linkage failure with two published SLF4J API jars."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from urllib.request import urlopen


# SHA-256 of the original Maven Central artifacts.
HASHES = {
    "1.7.36": "d3ef575e3e4979678dc01bf1dcce51021493b4d11fb7f1be8ad982877c16a1c0",
    "2.0.17": "7b751d952061954d5abfed7181c1f645d336091b679891591d63329c622eb832",
}
SOURCE = """package fixture;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
public class Checkout {
    public static void main(String[] args) {
        Logger logger = LoggerFactory.getLogger("checkout");
        logger.atInfo().log("checkout complete");
        System.out.println("checkout complete");
    }
}
"""
DESC = "()Lorg/slf4j/spi/LoggingEventBuilder;"


def fetch(directory, version):
    name = f"slf4j-api-{version}.jar"
    url = f"https://repo.maven.apache.org/maven2/org/slf4j/slf4j-api/{version}/{name}"
    with urlopen(url, timeout=30) as response:
        payload = response.read(1024 * 1024 + 1)
    if hashlib.sha256(payload).hexdigest() != HASHES[version]:
        raise ValueError(f"SHA-256 mismatch for {name}")
    path = directory / name
    path.write_bytes(payload)
    return path


def java_tool(name):
    executable = name + (".exe" if os.name == "nt" else "")
    if os.environ.get("JAVA_HOME"):
        return str(Path(os.environ["JAVA_HOME"]) / "bin" / executable)
    path = shutil.which(executable)
    if not path:
        raise FileNotFoundError(f"Missing {name}. Set JAVA_HOME to a JDK 21 installation.")
    return path


def run(argv, expected=0):
    result = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=60)
    if result.returncode != expected:
        raise RuntimeError(f"Expected exit {expected}, got {result.returncode}\n{result.stdout}{result.stderr}")
    return result


def scan(launcher, jars, output, exit_code):
    args = [launcher, "scan", "--out", output, "--target", "21"]
    for jar in jars:
        args.extend(["--jar", jar])
    run(args, exit_code)
    return json.loads((output / "report.json").read_bytes())


def check(installation, work):
    launcher = installation / "bin" / ("linkagelens.bat" if os.name == "nt" else "linkagelens")
    old = fetch(work, "1.7.36")
    current = fetch(work, "2.0.17")
    source = work / "Checkout.java"
    source.write_text(SOURCE, encoding="utf-8")
    classes = work / "classes"
    classes.mkdir()
    run([java_tool("javac"), "--release", "8", "-g", "-cp", current, "-d", classes, source])
    consumer = work / "checkout.jar"
    with zipfile.ZipFile(consumer, "w") as jar:
        jar.write(classes / "fixture/Checkout.class", "fixture/Checkout.class")

    broken = [consumer, old, current]
    fixed = [consumer, current]
    java = java_tool("java")
    failed = run([java, "-cp", os.pathsep.join(map(str, broken)), "fixture.Checkout"], 1)
    if "java.lang.NoSuchMethodError:" not in failed.stderr or "org.slf4j.Logger.atInfo()" not in failed.stderr:
        raise AssertionError(f"Expected the SLF4J atInfo linkage error\n{failed.stderr}")
    passed = run([java, "-cp", os.pathsep.join(map(str, fixed)), "fixture.Checkout"])
    if passed.stdout.strip() != "checkout complete":
        raise AssertionError(f"Unexpected fixed application output: {passed.stdout}")

    evidence = scan(launcher, broken, work / "broken", 1)
    jars = {item["index"]: item for item in evidence["artifacts"]}
    matches = [r for r in evidence["findings"] if r["caller"] == "fixture.Checkout"
               and r["callerMethod"] == "main" and r["owner"] == "org.slf4j.Logger"
               and r["member"] == "atInfo" and r["descriptor"] == DESC and r["code"] == "MISSING_METHOD"]
    if evidence["status"] != "FAIL" or len(matches) != 1:
        raise AssertionError(f"Expected one finding for the fixture's atInfo call: {matches}")
    call = matches[0]
    selected = jars[call["selectedArtifact"]]
    alternative = jars[call["alternativeArtifact"]]
    if (selected["name"], selected["sha256"]) != (old.name, HASHES["1.7.36"]):
        raise AssertionError(f"Unexpected selected artifact: {selected}")
    if (alternative["name"], alternative["sha256"]) != (current.name, HASHES["2.0.17"]):
        raise AssertionError(f"Unexpected alternative artifact: {alternative}")
    clean = scan(launcher, fixed, work / "fixed", 0)
    if clean["status"] != "PASS" or clean["findings"]:
        raise AssertionError(f"Expected the corrected classpath to pass: {clean['status']}")
    print(f"Matched fixture.Checkout.main line {call['line']}: {call['opcode']} org.slf4j.Logger.atInfo{DESC}")
    print("SLF4J smoke passed. The JVM and scan reproduced the failure and accepted the fix.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install-dir", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="linkagelens-slf4j-") as temp:
        check(args.install_dir.resolve(), Path(temp))
