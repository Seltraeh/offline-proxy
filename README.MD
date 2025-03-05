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

| Preset Name     | Description                                                                 |
|-----------------|-------------------------------------------------------------------------|
| `deploy-vs`     | Configuration for deploying to the BF client using Visual Studio as the compiler |
| `deploy-mingw`  | Configuration for deploying to the BF client using MinGW as the compiler      |
| `debug-vs`      | Configuration for testing the BF client with a local server using Visual Studio |
| `debug-mingw`   | Configuration for testing the BF client with a local server using MinGW       |

- **Note**: The `debug-vs` preset (used in the example above) is recommended for initial testing and development. Adjust the preset and configuration (`Debug` or `RelWithDebInfo`) based on your deployment or testing needs.

## Next Steps: Building the Game Client
Once you’ve successfully built the offline proxy and obtained `libcurl.dll`, refer to the Brave Frontier offline mod documentation for instructions on integrating the proxy with the game client and setting up the local server. This typically involves:
- Copying `libcurl.dll` to the appropriate directory in your Brave Frontier installation.
- Configuring the game to connect to your local server (details vary by mod version and setup).

For specific guidance, consult the Brave Frontier offline mod’s official repository or community forums.

## License
This project is licensed under the GNU Affero General Public License (AGPL) 3.0 or later. For more details, see the `LICENSE` file in the repository.
