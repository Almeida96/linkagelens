"""Read an installed LinkageLens report with the official MCP Python SDK."""

import argparse
import asyncio
import json
import os
import shutil
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def call(client, name, **args):
    result = await client.call_tool(name, args)
    assert not result.isError, result.content
    assert json.loads(result.content[0].text) == result.structuredContent
    return result.structuredContent


async def check(install_dir: Path, report_path: Path) -> None:
    before = report_path.read_bytes()
    report = json.loads(before)
    artifacts = {item["index"]: item for item in report["artifacts"]}
    lib = install_dir / "lib"
    if not list(lib.glob("*.jar")):
        raise ValueError(f"Missing distribution jars in {lib}")
    java_home = os.environ.get("JAVA_HOME")
    java_name = "java.exe" if os.name == "nt" else "java"
    java = str(Path(java_home) / "bin" / java_name) if java_home else shutil.which("java")
    if not java:
        raise ValueError("A Java 21 runtime is required")
    server = StdioServerParameters(
        command=java,
        args=["-cp", str(lib / "*"), "io.github.almeida96.linkagelens.Main",
              "mcp", "--report", str(report_path)],
    )
    async with stdio_client(server) as (reader, writer), ClientSession(reader, writer) as client:
        greeting = await client.initialize()
        assert greeting.serverInfo.name == "linkagelens"
        await client.send_ping()
        inventory = await client.list_tools()
        assert {tool.name for tool in inventory.tools} == {
            "linkage_summary", "list_findings", "list_duplicates", "inspect_duplicate"
        }
        assert all(tool.annotations.readOnlyHint and not tool.annotations.openWorldHint for tool in inventory.tools)
        summary = await call(client, "linkage_summary")
        assert summary["status"] == report["status"] and summary["targetRelease"] == report["targetRelease"]
        assert summary["artifactCount"] == len(artifacts)
        findings = await call(client, "list_findings", limit=1)
        assert findings["total"] == summary["findingCount"] == len(report["findings"])
        assert findings["findings"] == report["findings"][:1]
        if findings["total"]:
            owner = report["findings"][0]["owner"]
            filtered = await call(client, "list_findings", owner=owner, limit=1)
            expected = [item for item in report["findings"] if item["owner"] == owner]
            assert filtered["total"] == len(expected) and filtered["findings"] == expected[:1]
        page = await call(client, "list_duplicates", limit=1)
        assert page["total"] == summary["duplicateCount"] == len(report["duplicates"])
        if report["duplicates"]:
            duplicate = report["duplicates"][0]
            name = duplicate["className"]
            row = page["duplicates"][0]
            assert row["className"] == name and row["identical"] == duplicate["identical"]
            assert row["providerCount"] == len(duplicate["providers"])
            for offset in (0, len(duplicate["providers"]) - 1):
                inspected = await call(client, "inspect_duplicate", className=name, offset=offset, limit=1)
                provider = inspected["providers"][0]
                expected = duplicate["providers"][offset]
                artifact = artifacts[expected["artifact"]]
                assert provider == {**{k: expected[k] for k in ("artifact", "entry", "sha256")},
                                    "artifactName": artifact["name"], "artifactSha256": artifact["sha256"],
                                    "selected": offset == 0}
                assert inspected["selectedArtifact"] == duplicate["providers"][0]["artifact"]
                assert inspected["nextOffset"] == (offset + 1 if offset + 1 < len(duplicate["providers"]) else None)
        invalid = await client.call_tool("linkage_summary", {"path": "other.json"})
        assert invalid.isError
    assert report_path.read_bytes() == before
    print(f"MCP smoke passed for {report_path} ({report['status']})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    asyncio.run(asyncio.wait_for(check(args.install_dir.resolve(), args.report.resolve()), timeout=30))
