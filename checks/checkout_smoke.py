"""Compare the installed scanner's evidence with the JVM on the bundled checkout example."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def run(args, expected=0):
    result = subprocess.run(args, capture_output=True, text=True, timeout=120)
    if result.returncode != expected:
        raise RuntimeError(f"Expected exit {expected}, got {result.returncode}\n{result.stdout}\n{result.stderr}")
    return result


def verify(install_dir):
    cli = install_dir.resolve() / "bin" / ("linkagelens.bat" if os.name == "nt" else "linkagelens")
    java_home = os.environ.get("JAVA_HOME")
    java = Path(java_home) / "bin" / ("java.exe" if os.name == "nt" else "java") if java_home else "java"
    with tempfile.TemporaryDirectory(prefix="linkage-lens-") as temp:
        root = Path(temp)
        demo = root / "checkout demo"
        run([cli, "demo", "--out", demo])
        for name, status in (("broken", "FAIL"), ("reordered", "WARN"), ("fixed", "PASS")):
            case = demo / name
            jar_paths = [(case / item).resolve() for item in (case / "classpath.txt").read_text().splitlines()]
            report = json.loads((case / "report.json").read_bytes())
            assert report["status"] == status
            assert [hashlib.sha256(jar.read_bytes()).hexdigest() for jar in jar_paths] == [
                jar["sha256"] for jar in report["artifacts"]
            ]
            failing = name == "broken"
            # Only the synthetic checkout fixture built from this repository is executed.
            result = run([java, "-cp", os.pathsep.join(map(str, jar_paths)), "demo.checkout.Checkout"], int(failing))
            if failing:
                finding, = report["findings"]
                assert "java.lang.NoSuchMethodError" in result.stderr and "Tariff.quote(long, int)" in result.stderr
                assert finding["code"] == "MISSING_METHOD" and finding["descriptor"] == "(JI)J"
                assert finding["owner"] == "demo.pricing.Tariff" and finding["caller"] == "demo.checkout.Checkout"
                assert finding["line"] > 0 and f"Checkout.java:{finding['line']}" in result.stderr
                assert jar_paths[finding["selectedArtifact"]].name == "tariff-legacy.jar"
                assert jar_paths[finding["alternativeArtifact"]].name == "tariff-current.jar"
            else:
                assert result.stdout.strip() == "Order total: 1080 cents" and not report["findings"]
            replay = root / (name + "-replay")
            run([cli, "scan", "--target", "21", "--classpath-file", case / "classpath.txt", "--out", replay],
                int(failing))
            assert (case / "report.json").read_bytes() == (replay / "report.json").read_bytes()
            if name == "reordered":
                run([cli, "scan", "--strict", "--classpath-file", case / "classpath.txt", "--out", root / "strict"], 1)
            print(f"{name}: {status}, JVM {'raised NoSuchMethodError' if failing else 'returned 1080 cents'}")
        run([cli, "demo", "--out", demo], 2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install-dir", type=Path, required=True)
    verify(parser.parse_args().install_dir)
