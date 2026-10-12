---
id: c_systems_embedded
version: 1
covers: []
standards: ["cwe", "cert-c", "misra-c2012"]
max_tokens: 1500
---
## Runtime and framework model
C code built freestanding or near the hardware: OS kernels and drivers, firmware, bootloaders,
RTOS applications (FreeRTOS, Zephyr, ThreadX), or minimal-libc userland (newlib, musl, picolibc).
There may be no MMU, no ASLR, no stack canaries, and no separation between tasks. Interrupt
handlers and DMA engines run concurrently with ordinary code.

## Trust and interface layer
- Inputs arrive through peripherals and buses: UART, USB descriptors and control transfers,
  Bluetooth and Wi-Fi frames, CAN, SPI/I2C sensors, network stacks (lwIP, embedded TCP/IP),
  firmware update images, and ioctl or syscall arguments from user space.
- In kernels, user pointers are hostile: they may be unmapped, change between reads, or point into
  kernel memory.
- Firmware update and secure boot chains are the main trust anchor: whoever can load code owns
  the device.

## Idiomatic security mechanisms
- Kernel user-copy helpers (`copy_from_user`, `get_user`, `access_ok`) that copy once into kernel
  memory before validation.
- Bounded descriptor parsing with explicit `bLength`/`wTotalLength` checks against buffer size.
- MPU regions, stack guards, and watchdogs on RTOS targets; MISRA C rule sets and static analyzers.
- Signed firmware images verified before flashing and before boot, with rollback protection and
  constant-time signature comparison.
- Volatile and memory-barrier discipline for shared registers and ISR-shared variables.

## Stack-specific pitfalls
- Double fetch: reading a user-space or shared-memory length twice, validating the first copy and
  using the second.
- Descriptor or packet lengths trusted from the device or radio peer when copying into fixed
  static buffers.
- Integer promotions on `uint8_t`/`uint16_t` arithmetic, signed `char` indexing tables, shifts by
  input-controlled counts.
- Interrupt and task races on unprotected globals; missing interrupt masking or locks around
  shared data.
- Debug interfaces (JTAG, SWD, UART shells) left enabled; hard-coded service passwords.
- Update images verified for integrity but not authenticity, or verified after partial flashing.
- Uninitialized stack or struct padding copied to user space (kernel info leaks).
- DMA buffers placed where the device can overwrite descriptors or code; IOMMU not configured.

## Build and deployment facts to check
- Target architecture, toolchain, and whether the build is freestanding (`-ffreestanding`,
  `-nostdlib`) or hosted.
- Enabled hardening on the target: stack protector, MPU configuration, `CONFIG_*` kernel options
  such as `HARDENED_USERCOPY`, `FORTIFY_SOURCE`, `STACKPROTECTOR`.
- Which protocol stacks and drivers are compiled in by Kconfig or board configuration.
- Debug-port and shell configuration in production builds.
- Boot and update key provisioning and whether verification can be disabled by a fuse or flag.
