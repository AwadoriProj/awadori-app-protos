from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.parse
import zipfile
from pathlib import Path

os.environ.setdefault("PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION", "python")

import requests

ROOT = Path(__file__).resolve().parent
PACKAGE = "com.bilibili.sirius"
DOWNLOAD_URL = f"https://d.apkpure.net/b/XAPK/{PACKAGE}?version=latest"
REGION = ROOT / "global"
PROTO_DIR = REGION / "protobufs"
VERSION_FILE = REGION / "appver.json"
WORK = ROOT / ".work"
DUMPER_ZIP = ROOT / "ill2cppdumper.zip"
TOOLS = ROOT / "tools"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131 Safari/537.36"


def request_session() -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    return session


def probe_latest(session: requests.Session) -> tuple[str, str]:
    response = session.get(DOWNLOAD_URL, allow_redirects=False, stream=True, timeout=45)
    try:
        if response.status_code not in (301, 302, 303, 307, 308):
            raise RuntimeError(
                f"APKPure latest endpoint {DOWNLOAD_URL} returned HTTP {response.status_code}"
            )
        location = response.headers.get("Location", "")
    finally:
        response.close()
    filename = urllib.parse.parse_qs(urllib.parse.urlparse(location).query).get("filename", [""])[0]
    match = re.search(r"_(\d+(?:\.\d+)+)_APKPure\.xapk$", urllib.parse.unquote(filename), re.I)
    if not match:
        raise RuntimeError(f"could not read Our Notes version from APKPure redirect: {filename or location}")
    return match.group(1), location


def stored_version() -> str:
    try:
        return json.loads(VERSION_FILE.read_text(encoding="utf-8")).get("version_name", "")
    except (OSError, json.JSONDecodeError):
        return ""


def source_proto_files() -> list[Path]:
    return sorted(
        path for path in PROTO_DIR.rglob("*.proto")
        if path.relative_to(PROTO_DIR).parts[:1] != ("google",)
        and not path.name.startswith("merged")
    )


def stored_metadata() -> dict:
    try:
        return json.loads(VERSION_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def download_xapk(session: requests.Session, location: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_suffix(destination.suffix + ".part")
    response = session.get(location or DOWNLOAD_URL, stream=True, timeout=(30, 180))
    response.raise_for_status()
    try:
        with partial.open("wb") as output:
            for chunk in response.iter_content(1024 * 1024):
                if chunk:
                    output.write(chunk)
    except Exception:
        partial.unlink(missing_ok=True)
        raise
    finally:
        response.close()
    if not zipfile.is_zipfile(partial):
        partial.unlink(missing_ok=True)
        raise RuntimeError("APKPure response is not a valid XAPK archive")
    partial.replace(destination)


def xapk_version(archive: Path) -> tuple[str, int]:
    with zipfile.ZipFile(archive) as zf:
        try:
            manifest = json.loads(zf.read("manifest.json"))
            name = str(manifest.get("version_name", ""))
            code = int(manifest.get("version_code", 0))
            if name and code:
                return name, code
        except (KeyError, ValueError, json.JSONDecodeError):
            pass
        try:
            from pyaxmlparser import APK
        except ImportError as error:
            raise RuntimeError("install pyaxmlparser to read the XAPK version") from error
        apks = [name for name in zf.namelist() if name.lower().endswith(".apk")]
        base_apk = next((name for name in apks if Path(name).name.lower() == f"{PACKAGE}.apk"), None)
        if base_apk is None:
            raise RuntimeError("XAPK does not contain the Our Notes base APK")
        data = zf.read(base_apk)
    base_path = WORK / "base.apk"
    base_path.write_bytes(data)
    apk = APK(str(base_path))
    if not apk.version_name or apk.version_code is None:
        raise RuntimeError("could not read app version from the base APK")
    return apk.version_name, int(apk.version_code)


def extract_inputs(archive: Path) -> tuple[Path, Path]:
    WORK.mkdir(parents=True, exist_ok=True)
    metadata_path = WORK / "global-metadata.dat"
    library_path = WORK / "libil2cpp.so"
    metadata_found = False
    library_found = False
    with zipfile.ZipFile(archive) as xapk:
        inner_apks = [name for name in xapk.namelist() if name.lower().endswith(".apk")]
        if not inner_apks:
            raise RuntimeError("XAPK contains no split APKs")
        for inner_name in inner_apks:
            inner_data = io.BytesIO(xapk.read(inner_name))
            with zipfile.ZipFile(inner_data) as apk:
                members = apk.namelist()
                metadata_member = next((name for name in members if name.replace("\\", "/").endswith("assets/bin/Data/Managed/Metadata/global-metadata.dat")), None)
                library_member = next((name for name in members if name.replace("\\", "/").endswith("lib/arm64-v8a/libil2cpp.so")), None)
                if metadata_member and not metadata_found:
                    with apk.open(metadata_member) as source, metadata_path.open("wb") as target:
                        shutil.copyfileobj(source, target)
                    metadata_found = True
                if library_member and not library_found:
                    with apk.open(library_member) as source, library_path.open("wb") as target:
                        shutil.copyfileobj(source, target)
                    library_found = True
            del inner_data
            if metadata_found and library_found:
                break
    if not metadata_found:
        raise RuntimeError("global-metadata.dat was not found in the base APK")
    if not library_found:
        raise RuntimeError("arm64-v8a/libil2cpp.so was not found in the config split")
    return metadata_path, library_path


def run_tool(args: list[str]) -> str:
    result = subprocess.run(args, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError(f"command failed: {' '.join(args)}\n{result.stdout[-5000:]}")
    return result.stdout


def decrypt_inputs(metadata_path: Path, library_path: Path) -> tuple[Path, Path]:
    decrypted_metadata = WORK / "global-metadata.decrypted.dat"
    decrypted_library = WORK / "libil2cpp.decrypted.so"
    metadata_tool = TOOLS / "metadata.py"
    library_tool = TOOLS / "libil2cpp.py"
    run_tool([sys.executable, str(metadata_tool), "decrypt", str(metadata_path), str(decrypted_metadata)])
    result = subprocess.run([sys.executable, str(library_tool), "decrypt", str(library_path), str(decrypted_library)], cwd=TOOLS, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if result.returncode:
        seed_result = run_tool([sys.executable, str(library_tool), "find-seed", str(library_path)])
        match = re.search(r"seed:\s*(0x[0-9a-f]+)", seed_result, re.I)
        if not match:
            raise RuntimeError(f"libil2cpp decryption failed and no seed was found\n{result.stdout[-3000:]}\n{seed_result}")
        run_tool([sys.executable, str(library_tool), "decrypt", str(library_path), str(decrypted_library), "--seed", match.group(1)])
    if decrypted_metadata.stat().st_size < 8 or decrypted_metadata.read_bytes()[:4] != bytes.fromhex("af1bb1fa"):
        raise RuntimeError("metadata decryption did not produce an IL2CPP metadata header")
    if decrypted_library.read_bytes()[:4] != b"\x7fELF":
        raise RuntimeError("libil2cpp decryption did not produce an ELF library")
    return decrypted_metadata, decrypted_library


def prepare_dumper() -> Path:
    dumper = WORK / "il2cppdumper"
    exe = dumper / "Il2CppDumper.exe"
    if not exe.exists():
        dumper.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(DUMPER_ZIP) as zf:
            zf.extractall(dumper)
    config_path = dumper / "config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["RequireAnyKey"] = False
    config["GenerateDummyDll"] = False
    config["GenerateStruct"] = True
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return dumper


def dump_il2cpp(metadata_path: Path, library_path: Path) -> tuple[Path, Path]:
    dumper = prepare_dumper()
    output = WORK / "il2cpp-output"
    output.mkdir(parents=True, exist_ok=True)
    for name in ("dump.cs", "stringliteral.json"):
        (dumper / name).unlink(missing_ok=True)
        (output / name).unlink(missing_ok=True)
    result = subprocess.run([str(dumper / "Il2CppDumper.exe"), str(library_path), str(metadata_path), str(output)], cwd=dumper, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    source_dir = dumper if (dumper / "dump.cs").exists() else output
    dump_file, literals_file = source_dir / "dump.cs", source_dir / "stringliteral.json"
    if not dump_file.is_file() or not literals_file.is_file():
        raise RuntimeError(f"Il2CppDumper did not produce dump.cs and stringliteral.json\n{result.stdout[-5000:]}")
    if source_dir != output:
        shutil.copy2(dump_file, output / dump_file.name)
        shutil.copy2(literals_file, output / literals_file.name)
        dump_file, literals_file = output / dump_file.name, output / literals_file.name
    return dump_file, literals_file


def dump_protobufs(library_path: Path, dump_file: Path, literals_file: Path) -> int:
    sys.path.insert(0, str(ROOT))
    import dump_protos

    staging = WORK / "protobufs"
    if staging.exists():
        shutil.rmtree(staging)
    count = dump_protos.dump(library_path, dump_file, literals_file, staging)
    if count <= 0:
        raise RuntimeError("protobuf dump returned no descriptors")
    previous = REGION / "protobufs.previous"
    if previous.exists():
        shutil.rmtree(previous)
    if PROTO_DIR.exists():
        PROTO_DIR.replace(previous)
    staging.replace(PROTO_DIR)
    if previous.exists():
        shutil.rmtree(previous)
    return count


def generate_go_bindings() -> int:
    proto_files = source_proto_files()
    mappings = []
    for path in proto_files:
        relative = path.relative_to(PROTO_DIR).as_posix()
        source = path.read_text(encoding="utf-8")
        match = re.search(r"^\s*package\s+([A-Za-z0-9_.]+)\s*;", source, re.M)
        if not match:
            continue
        proto_package = match.group(1)
        package_name = proto_package.rsplit(".", 1)[-1].replace("-", "_")
        import_path = "private-notes/game/proto/" + proto_package.replace(".", "/")
        mappings.append((relative, import_path + ";" + package_name))
    if not mappings:
        raise RuntimeError("no application protobuf files found for Go generation")

    go_plugin = shutil.which("protoc-gen-go")
    grpc_plugin = shutil.which("protoc-gen-go-grpc")
    if not go_plugin or not grpc_plugin:
        raise RuntimeError("install protoc-gen-go and protoc-gen-go-grpc before updating")
    staging = WORK / "generated-proto"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    command = [
        sys.executable,
        "-m",
        "grpc_tools.protoc",
        f"-I{PROTO_DIR}",
        f"--plugin=protoc-gen-go={go_plugin}",
        f"--plugin=protoc-gen-go-grpc={grpc_plugin}",
        f"--go_out={staging}",
        "--go_opt=paths=source_relative",
        f"--go-grpc_out={staging}",
        "--go-grpc_opt=paths=source_relative",
    ]
    for relative, target in mappings:
        command.extend((f"--go_opt=M{relative}={target}", f"--go-grpc_opt=M{relative}={target}"))
    command.extend(str(path) for path in proto_files)
    result = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError(f"Go protobuf generation failed\n{result.stdout[-5000:]}")
    generated = list(staging.rglob("*.pb.go"))
    if not generated:
        raise RuntimeError("Go protobuf generation produced no files")
    target = ROOT / "proto"
    previous = ROOT / "proto.previous"
    if previous.exists():
        shutil.rmtree(previous)
    if target.exists():
        target.replace(previous)
    staging.replace(target)
    if previous.exists():
        shutil.rmtree(previous)
    return len(generated)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    session = request_session()
    version_name, location = probe_latest(session)
    if not args.force and version_name == stored_version() and PROTO_DIR.is_dir():
        metadata = stored_metadata()
        required = int(metadata.get("proto_file_count", len(source_proto_files())))
        existing = len(list((ROOT / "proto").rglob("*.pb.go")))
        if existing >= required:
            print(f"Our Notes {version_name}: protos already up to date")
            return
        generated_count = generate_go_bindings()
        metadata["proto_file_count"] = len(source_proto_files())
        metadata["go_generated_files"] = generated_count
        VERSION_FILE.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
        print(f"generated {generated_count} Go files from the existing {version_name} proto dump")
        return
    archive = WORK / "our-notes-latest.xapk"
    print(f"downloading Our Notes {version_name} XAPK from APKPure")
    download_xapk(session, location, archive)
    archive_version, version_code = xapk_version(archive)
    if archive_version != version_name:
        raise RuntimeError(f"APKPure redirect says {version_name}, XAPK manifest says {archive_version}")
    metadata_path, library_path = extract_inputs(archive)
    decrypted_metadata, decrypted_library = decrypt_inputs(metadata_path, library_path)
    dump_file, literals_file = dump_il2cpp(decrypted_metadata, decrypted_library)
    count = dump_protobufs(decrypted_library, dump_file, literals_file)
    generated_count = generate_go_bindings()
    REGION.mkdir(parents=True, exist_ok=True)
    VERSION_FILE.write_text(json.dumps({
        "package": PACKAGE,
        "version_name": archive_version,
        "version_code": version_code,
        "source": DOWNLOAD_URL,
        "xapk_sha256": file_sha256(archive),
        "protobuf_count": count,
        "proto_file_count": len(source_proto_files()),
        "go_generated_files": generated_count,
    }, indent=2) + "\n", encoding="utf-8")
    print(f"Our Notes {archive_version} ({version_code}): dumped {count} protobuf descriptors and generated {generated_count} Go files")


if __name__ == "__main__":
    main()
