# Our Notes App Protos

This repository stores protobuf descriptors extracted from the Android client and refreshes them when APKPure publishes a newer XAPK for `com.bilibili.sirius`.

`global/protobufs` contains the current schema dump. `proto` contains generated Go protobuf bindings consumed by `private-notes/game/proto`. `global/appver.json` records the app version that produced them. `updater.py` probes the APKPure XAPK endpoint, downloads the base and split APKs, decrypts `global-metadata.dat` and the ARM64 `libil2cpp.so` with the scripts in `tools`, runs Il2CppDumper, extracts protobuf descriptors, and regenerates Go bindings.

Install Python 3.11, .NET 8, Go, and the requirements. Install `protoc-gen-go` and `protoc-gen-go-grpc` into `PATH`, then run:

```powershell
python updater.py
```

Use `python updater.py --force` to redownload and dump the latest XAPK even when the version matches. Temporary APKs, decrypted files, and dumper output are kept in `.work` and ignored by Git.

The scheduled GitHub Actions workflow checks APKPure every six hours and commits changed schemas, generated Go bindings, and version metadata.
