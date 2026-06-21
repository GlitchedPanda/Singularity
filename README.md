# Singularity

**Singularity** is a proof-of-concept for mapping unsigned kernel drivers using a custom UEFI DXE runtime driver.

The usermode mapper (`DriverMapper`) is a fork of [kdmapper](https://github.com/TheCruZ/kdmapper) that replaces the vulnerable-driver communication layer with a custom UEFI DXE runtime driver (`SingularityPkg`).

## How the UEFI DXE Driver Works

Instead of relying on a vulnerable kernel driver to execute arbitrary code in kernel mode, Singularity uses a UEFI DXE driver that runs in firmware space and hooks the EFI Runtime Service `SetVariable`.

### Architecture

```
User Mode (mapper.exe)
    |
    |  NtSetSystemEnvironmentValueEx("Singularity42", MemoryCommand)
    v
Windows Kernel (ntoskrnl)
    |
    |  gRT->SetVariable("Singularity42")
    v
UEFI Runtime (SingularityDxe.efi)
    |
    |  HookedSetVariable -> RunCommand
    v
    DriverBuffer (32 MB EfiRuntimeServicesCode pool)
        |
        |  Driver image, allocations, execution
        v
    Arbitrary kernel-mode code
```

### Step-by-step

1. **Installation** - The DXE driver is loaded at boot (via UEFI shell, DXE driver injection, or boot option). On entry (`DxeDriverEntry`), it:
   - Allocates a 32 MB `EfiRuntimeServicesCode` buffer called `DriverBuffer` for hosting mapped drivers
   - Hooks `gRT->SetVariable` by patching the EFI Runtime Services Table, redirecting all calls to `HookedSetVariable`
   - Registers event handlers for `SetVirtualAddressMap` and `ExitBootServices` to manage the boot-to-runtime transition

2. **SetVariable Hook** - The hook checks if the variable name is `"Singularity42"`. If so, it interprets the payload as a `MemoryCommand` structure and passes it to `RunCommand`. All other `SetVariable` calls are forwarded to the original function.

3. **Command Operations** - `RunCommand` supports these operations:

   | Op | Function | Description |
   |----|----------|-------------|
   | 0 | `memcpy(dst, src, size)` | Copies memory between arbitrary addresses |
   | 1 | `AllocatePool` | Reports `DriverBuffer` address back to the caller |
   | 3 | `CallStdcall(target)` | Calls `void __stdcall()` inside `DriverBuffer` |
   | 4 | `CallFastcall(target)` | Calls `void __fastcall()` inside `DriverBuffer` |
   | 5 | `CallDriverEntry(target)` | Calls a `DriverEntry`-style function inside `DriverBuffer`, returns NTSTATUS |

   All calls are bounds-checked against `DriverBuffer` to prevent executing arbitrary UEFI addresses.

4. **Virtual Address Transition** - When Windows calls `SetVirtualAddressMap`, the DXE driver converts its pointers (`oSetVariable`, `DriverBuffer`) using `ConvertPointer`. After `ExitBootServices`, the hook activates fully and begins processing commands.

### Mapper Flow (DriverMapper)

1. Enable `SeSystemEnvironmentPrivilege` for the calling process
2. Read the target `.sys` driver into memory
3. Parse PE headers, relocate the image, resolve imports with fallback to `ntoskrnl.exe`
4. Fix the stack cookie (`__security_cookie`)
5. Allocate kernel memory via the DXE driver's operation 1 (reports `DriverBuffer` address)
6. Write the fixed driver image into `DriverBuffer`
7. Call the driver's entry point via operation 5
8. Optionally free the pool after the driver exits

### Kernel-Mode Hiding

After mapping, `ClearMmUnloadedDrivers` removes the driver entry from `MmUnloadedDrivers` via the system handle table, preventing detection by `NtQuerySystemInformation`.

## Usage

```
Mapper.exe [--free] [--PassAllocationPtr] [--copy-header] driver.sys
```

| Flag | Description |
|------|-------------|
| `--free` | Free the allocated pool after the driver's entry point returns |
| `--PassAllocationPtr` | Pass the allocation address as the first parameter to `DriverEntry` |
| `--copy-header` | Keep the PE header intact (default behavior strips it) |

## Building

### Prerequisites

- Visual Studio 2026 (or your preferred version)
- [EDK2](https://github.com/tianocore/edk2) properly set up
- NASM assembler (required by EDK2)

### Build the UEFI DXE Driver (SingularityPkg)

1. Clone and set up EDK2:

   ```powershell
   git clone https://github.com/tianocore/edk2.git
   cd edk2
   git submodule update --init
   edksetup.bat
   ```

2. Copy the `SingularityPkg` folder into the EDK2 workspace root (next to `MdePkg`, `UefiCpuPkg`, etc.).

3. Build:

   ```
   build -p SingularityPkg\SingularityPkg.dsc -a X64 -t VS2026 -b RELEASE
   ```

   The output `SingularityDxe.efi` will be under `Build\SingularityPkg\RELEASE_VS2026\X64\`.

### Build the Mapper (DriverMapper)

Open `DriverMapper.slnx` in Visual Studio and build the solution.

## Deploying the DXE Driver

### Prerequisites

- A **FAT32 formatted USB drive** (at least 64 MB)
- **Shell.efi** from EDK2 (built from `edk2/ShellPkg`) or downloaded from a release
- The compiled `SingularityDxe.efi` binary

### Steps

1. **Format a USB drive as FAT32** and copy the following files to its root:
   - `Shell.efi` (renamed to `bootx64.efi` and placed under `EFI\BOOT\` so the firmware boots into it automatically)
   - `SingularityDxe.efi` (placed anywhere on the drive, e.g. `SingularityDxe.efi`)

   Expected layout:
   ```
   USB drive (FAT32)
   └── EFI
       └── BOOT
           └── bootx64.efi   (Shell.efi)
   └── SingularityDxe.efi
   ```

2. **Boot from the USB drive** - Enter your BIOS/UEFI boot menu and select the USB drive. The UEFI Shell will launch.

3. **Load the DXE driver** - At the UEFI Shell prompt, find the USB drive (typically `fs0:`) and run:

   ```
   fs0:
   load SingularityDxe.efi
   ```

   If successful, the driver will print its banner, allocate `DriverBuffer`, hook `SetVariable`, and register the virtual address / exit-boot events.

4. **Exit back to Windows** - Once the driver is loaded, find the Windows Boot Manager and run it:

   ```
   fs0:\EFI\BOOT\bootx64.efi   (not this - this is the shell again)
   ```

   Instead, identify the Windows drive (e.g. `fs1:`) and run:

   ```
   fs1:\EFI\Microsoft\Boot\bootmgfw.efi
   ```

   Windows will resume normal booting with `SingularityDxe.efi` now active in memory.

5. **Run the mapper** - After Windows boots, run `mapper.exe` as administrator. It will communicate with the loaded DXE driver through EFI runtime variables to map your unsigned driver.

### Notes

- If you have Secure Boot enabled, you may need to disable it or sign the DXE driver appropriately.
- The DXE driver persists for the current boot session only. You must re-load it after every reboot.
- You can identify available UEFI file systems at the shell prompt with the `map` command.
- `Shell.efi` can be built from EDK2 (`build -p ShellPkg\ShellPkg.dsc -a X64 -t VS2026 -b RELEASE`) or obtained from a pre-built EDK2 release.

## Acknowledgements

This project is based on the following projects:

- [kdmapper](https://github.com/TheCruZ/kdmapper)
- [SamuelTulach/efi-memory](https://github.com/SamuelTulach/efi-memory)
- [EfiGuard](https://github.com/Mattiwatti/EfiGuard)

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.
