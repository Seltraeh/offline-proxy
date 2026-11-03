# Offline Proxy

This repository contains the source code for a DLL proxy used by the Brave Frontier offline mod. The proxy enables connection to a local server and embeds the offline server itself.

## Overview
The offline proxy is designed to facilitate offline gameplay for Brave Frontier by routing connections to a local server instead of the online service. This project is tailored for Windows users and includes specific compatibility and build requirements.

## Compatibility
- **Operating System**: Windows 8 or later (32-bit only)

## Requirements
To build the offline proxy, you’ll need the following tools:
- **Compiler**: Visual Studio 2022 or MinGW
- **Build System**: CMake 3.20 or later
- **Dependencies**: Ensure `vcpkg` is installed and configured (see Building section for details), with `libcurl` available.

## Building the Offline Proxy
Follow these steps to clone, configure, and build the offline proxy. This will generate `libcurl.dll`, which is necessary for the proxy to function.

1. **Clone the Repository**  
   Use Git to clone the repository:
   ```bash
   git clone https://github.com/decompfrontier/offline-proxy
   ```

2. **Set Up the Build Directory**  
   Create and navigate to a build directory within the cloned repository:
   ```bash
   cd offline-proxy
   mkdir build
   cd build
   ```

3. **Configure the Build with CMake**  
   Use CMake with a preset to configure the project. For testing with Visual Studio 2022, run:
   ```bash
   cmake --preset debug-vs ../
   ```
   - This preset is ideal for testing the Brave Frontier (BF) client with a local server using Visual Studio.

4. **Build the Project**  
   Compile the project to generate `libcurl.dll`:
   ```bash
   cmake --build . --config Debug
   ```
   - After a successful build, you’ll find `libcurl.dll` in the `bin/` directory of your `build` folder.

### Build Presets
CMake presets allow you to configure the build for different purposes and compilers. Choose the preset that matches your needs:

| Preset Name     | Description                                                                      |
|-----------------|----------------------------------------------------------------------------------|
| `deploy-vs`     | Configuration for deploying to the BF client using Visual Studio as the compiler |
| `deploy-mingw`  | Configuration for deploying to the BF client using MinGW as the compiler         |
| `debug-vs`      | Configuration for testing the BF client with a local server using Visual Studio  |
| `debug-mingw`   | Configuration for testing the BF client with a local server using MinGW          |

- **Note**: The `debug-vs` preset (used in the example above) is recommended for initial testing and development. Adjust the preset and configuration (`Debug` or `RelWithDebInfo`) based on your deployment or testing needs.

## Extra cmake variables
You can modify some of the Proxy behaviour by defining the CMake variables defined here:
| Name                      | Description                                                                              | Default value   |
| ------------------------- | ---------------------------------------------------------------------------------------- | --------------- |
| OFFLINEMOD_IP             | Sets the server IP which the proxy would connect                                         | 127.0.0.1       |
| OFFLINEMOD_PORT           | Sets the server port which the proxy would connect                                       | 9960            |
| OFFLINEMOD_DISABLE_HTTPS  | Enables the patches that allows the proxy to connect to an insecure (HTTP) connection    | 1 (true)        |
| OFFLINEMOD_FPS_CAP        | Compile-time fallback render-loop cap when the server probe fails. 0 disables.           | 60              |
| OFFLINEMOD_FPS_CAP_DIAG   | Compile in diagnostic logging for the FPS cap (%TEMP%\offlinemod_fps.log + OutputDebugString) | 0 (off)    |

### FPS cap server probe
The offline-proxy fetches the desired cap at startup via
`GET http://127.0.0.1:9960/offline_mod/fps_cap` (the existing InternetConnect
hook redirects to the configured server). The server returns a bare integer
in the body; the client applies it on the first valid `Render` call. If the
probe fails (server down, timeout, unreachable) the compile-time
`OFFLINEMOD_FPS_CAP` value remains in effect — the cap is never *un-capped*
by a missing server, just stuck at the build default.

To change the cap without rebuilding the DLL, edit `fps_cap` in the server's
`deploy/config.json` (under `plugins[0].config.server`) and relaunch the game.
The probe runs once per game launch; mid-game changes require a restart.

## Authoritative content provider (optional, off by default)

`-DOFFLINEMOD_CONTENT_PROVIDER=1` compiles a provider that reads selected assets
from the offline server's `game_content` into RAM instead of the client's
LocalState cache, so an edited server file (even a same-size edit) is used at
the next scene change without resetting the app. Nothing is written to disk.
Within a scene every read is bound to the version that scene started with
(protocol `bfcp 2`): a file changed on the server mid-scene fails like a
missing file until the next scene change, instead of mixing versions.

- It only activates when the client is the exact supported build (2.19.6.0 x86:
  module headers plus masked byte signatures of every hook site) **and** the
  server's `deploy/system/content_provider.json` says `"enabled": true`.
  Otherwise the game keeps its own cache and one line explains why.
- Which files it owns is the server's policy (Phase B: the Town map bundle and
  unit 60956); see `docs/CONTENT_PROVIDER_WINDOWS_CONTRACT.md` for the recovered
  loader contract, hook sites, byte forms and limits.
- Log: `%TEMP%\offlinemod_content.log` inside the app container (the package's
  `AC\Temp`), plus `OutputDebugString`: every owned read, existence decision,
  safe point, frame-time/memory window and tripwire.
- Tests: `build\tests\content_provider_tests.exe` (set `BF_APPX_DIR` to the
  extracted client so the signature table is checked against the real
  binaries). They build by default (`OFFLINEMOD_BUILD_TESTS`).
- For another client build, re-derive the sites in the contract document and
  regenerate the table with `python tests/fixtures/make_signatures.py <Appx folder>`.

| Variable | Description | Default |
| --- | --- | --- |
| OFFLINEMOD_CONTENT_PROVIDER | Compile the authoritative content provider | 0 (off) |
| OFFLINEMOD_BUILD_TESTS | Build `content_provider_tests` | ON |

## Next Steps: Building the Game Client
Once you’ve successfully built the offline proxy and obtained `libcurl.dll`, refer to the Brave Frontier offline mod documentation for instructions on integrating the proxy with the game client and setting up the local server. This typically involves:
- Copying `libcurl.dll` to the appropriate directory in your Brave Frontier installation.
- Configuring the game to connect to your local server (details vary by mod version and setup).

For specific guidance, consult the Brave Frontier offline mod’s official repository or community forums.

## License
This project is licensed under the GNU Affero General Public License (AGPL) 3.0 or later. For more details, see the `LICENSE` file in the repository.
