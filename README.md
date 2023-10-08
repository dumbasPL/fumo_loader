# fumo loader

All in one kernel-based DLL injector

## Features

- Manual map a dll into kernel memory and expose it to user-mode via page table manipulation
- Re-generate a unique, encrypted executable each time it is run and delete the old one
- Store the target dll in an encrypted form on disk (.fumo file)
- Tray icon and notifications that tell you about the status of the loader and allow you to abort the injection process
- Wait for certain modules to be loaded in the target process before injecting
- No running processes during injection (injects itself into a different process, explorer.exe by default)
- No open handles to the target process
- No new threads in the target process (injects using APCs from kernel)
- Compatible with:
  - Windows 10 20H1 to Windows 11 22H2 (x64) (in theory, only tested on W11 22H2)
  - Secure boot
  - PatchGuard
  - Driver Signature Enforcement
  - Vulnerable driver blocklist

## Limitations

- **NOT** Compatible with:
  - 32-bit Windows and 32-bit processes
  - Hypervisor code integrity (HVCI)
  - Good anti-cheats (this is designed for defeating user-mode anti-cheats)
  - Probably a bunch of anti-virus software
  - Old versions of Windows (before 20H1)
- Target DLL **MUST NOT** have:
  - Thread-local storage (TLS)
  - Vectored exception handlers (VEH) (adding a global handler manually is fine though)

## Caveats

- (Currently) it does not clean any traces of the vulnerable driver
  - Reboot before loading any "decent" anti-cheat if you don't feel like being insta banned
- The target process needs to have a thread that we can schedule APCs on (this is usually not an issue outside of very simple hello world programs that only have one thread)
- You might get random DEP violations because memory above 0x7FFF'FFFFFFFF is technically not valid user-mode memory (at least as far as Windows API's are concerned, your CPU doesn't care and will happily execute it, that's the whole idea behind this loader)
  - You will have to register an exception handler in your DLL that will catch the exception and return `EXCEPTION_CONTINUE_EXECUTION` whenever it encounters a DEP violation above 0x7FFF'FFFFFFFF

## Usage

### prepare the .fumo file

1. Download the latest release or build it yourself
2. Drag and drop a dll on to `fumo_encoder.exe`
  1. Fill out the process name
  2. Fill out what dll(s) to wait for before injecting

### Inject

1. Drag and drop the generated .fumo file on to `fumo.exe`
2. Wait for the success notification or error message box
3. Open the target process
4. Wait for the target dll(s) to be loaded
5. ...
6. Profit

## Building

### Requirements

- Visual Studio 2022 build tools (lower might work, but not tested)
- Windows Driver Kit 10 (WDK)
- CMake

### Configure and build

```sh
# configure the x64-windows preset
cmake --preset=x64-windows
# build the project
cmake --build --preset=Release
```

Or use the CMake integration built into your IDE of choice

## TODO (feel free to contribute)

- [ ] Add support for TLS
- [ ] Add support for VEH
- [ ] Do some trace cleaning

## Credits

### Libraries and tools used

- [KDU](https://github.com/hfiref0x/KDU) - the driver vulnerable mapper
- [libKDU](https://github.com/dumbasPL/libKDU) - My wrapper around KDU that turns it into a static library
- [lazy_importer](https://github.com/JustasMasiulis/lazy_importer) - inlined import resolution (used for position independent code)
- [xorstr](https://github.com/JustasMasiulis/xorstr) - inlined and encrypted strings (also used for position independent code)
- [FindWDK](https://github.com/SergiusTheBest/FindWDK) - CMake module for building windows drivers
- [CMake](https://cmake.org/) - amazing build system
- [@slnchyt](https://www.pixiv.net/en/artworks/35678304) - the tray icon

### Inspiration

- [ThePerfectInjector](https://github.com/can1357/ThePerfectInjector) - the original idea for this injection method
- [Blackbone](https://github.com/DarthTon/Blackbone) - well written kernel code that I used as a reference (and stole some code from)

## License

[MIT](LICENSE)
