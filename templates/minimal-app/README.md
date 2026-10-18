# Minimal native app

This C++ starter logs its launch, opens the active user's controller, and sends a
notification. Press Cross to log a marker; press Circle or Options to exit. It is
intended as a small base app for native homebrew work.

Build it from the repository root with `python3 tooling/native/build.py` after
setting `PS5_PAYLOAD_SDK` and the SDK's LLVM configuration. See the
[native build guide](../../docs/NATIVE_APP.md) for output and prerequisites.
Change `sce_sys/param.json` to use your own title and content IDs before
sharing an app. `tooling/native/build.py --template PATH` accepts another
folder with a `main.cpp` and `sce_sys/param.json`.

The local build succeeds with the tested SDK, but console installation, pad
behavior, notification behavior, and exit remain untested.
