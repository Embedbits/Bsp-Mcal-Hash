# HASH Peripheral Driver

This module provides an abstraction layer for the **hash processor** (`HASH`) of STM32 MCUs: the message digest of a buffer
or of a stream of data (SHA-1, SHA-2, and where the device has them MD5 and SHA-3) and the keyed digest HMAC. It offers a
one-shot request, an incremental interface (start - update - finish), the suspend and resume of an interrupted message and
the data transfer in DMA, interrupt or polling mode. It is a low-level MCAL module: it owns the HASH hardware, the
application and the other modules never touch the registers.

The public interface (`Hash_Port.h`, `Hash_Types.h`) is **identical for all supported families**. The implementation
for a family lives in its own branch (`Dev/<Family>` for development, `Releases/<Family>` for the released versions), so
a module or an application written against the interface does not change when the MCU family changes.

This README is the landing page and the **specification of the interface** (master). The family branches contain their
own README with everything that is specific to the family: the instances of the device, their settings and the status of
the implementation.

> **Status: design.** No implementation exists yet, the interface below is a proposal. Stories and branches follow.

---

## Intent and purpose

- Typical users are the **verification of a firmware image** (a secure boot, an update over the air - the image is read from
  the flash by DMA and hashed without the CPU), the **message authentication** (HMAC of a protocol frame, a token, a
  license), the **integrity of a stored configuration** and the building block of the TLS / signature stacks
  (a digest for ECDSA / RSA verification together with the Pka module).
- The hash processor works with 32-bit words in a fixed byte order, pads the message at the end and has its own
  input FIFO. The user wants none of it: the module takes **bytes** in any alignment and length, packs them into words,
  sets the data swapping of the hardware, handles the last incomplete word and the padding and returns the digest as a
  **byte array** in the order of the standard (the same bytes as `sha256sum`).
- A message can be interrupted. The hardware offers the suspend and the resume of a calculation (the context is saved and
  restored); the module exposes it as `Hash_Get_Context` / `Hash_Set_Context`, so a high priority user can compute a short
  digest in the middle of a long image verification without losing the work done.
- The module hides the differences between the families: the supported algorithms, the registers of the context, the
  number of digest words and the DMA request differ, the interface stays the same.

What the module is **not**: it does not implement the algorithms in software - a request for an algorithm the device does not
support returns an error (`Hash_Get_Capability` tells in advance). It does not store keys and it does not make a key
derivation (HKDF, PBKDF2) - they are middlewares built on the top of the HMAC.

---

## Concept

There is one HASH peripheral per device (`HASH_PERIPH_1`). The module supports three ways to use it:

| Way | Functions | Use |
|---|---|---|
| **One-shot** | `Hash_Set_Calculate` | The whole message is in one buffer, the digest is delivered to the output buffer and the complete callback. |
| **Incremental** | `Hash_Set_Start` - `Hash_Set_Update` (many times) - `Hash_Set_Finish` | The message comes in pieces (a stream, a flash image read in blocks). |
| **Suspend / resume** | `Hash_Get_Context`, `Hash_Set_Context` | An incremental calculation is saved into a `hash_Context_t` of the user and continued later; other messages can use the peripheral in between. |

Algorithms (`hash_Algorithm_t`) - only the ones the device supports are accepted:

| Group | Algorithms | Digest |
|---|---|---|
| MD5 | `HASH_ALGO_MD5` | 16 bytes |
| SHA-1 | `HASH_ALGO_SHA1` | 20 bytes |
| SHA-2 | `HASH_ALGO_SHA2_224`, `SHA2_256`, `SHA2_384`, `SHA2_512`, `SHA2_512_224`, `SHA2_512_256` | 28 ... 64 bytes |
| SHA-3 | `HASH_ALGO_SHA3_224`, `SHA3_256`, `SHA3_384`, `SHA3_512`, `SHAKE128`, `SHAKE256` (extendable output) | 28 ... 64 bytes, any length for SHAKE |

Every algorithm can be run as a plain hash or as an **HMAC** with a key of any length (`HASH_MODE_HASH`, `HASH_MODE_HMAC`).

Rules:

1. A request is accepted when the peripheral is idle (`Hash_Get_State`) and when the parameters are valid: a supported
   algorithm, a non-`HASH_NULL_PTR` buffer for a non-zero size, the digest buffer at least as long as the digest. Otherwise it
   returns an error and the hardware is not touched.
2. The request is **non-blocking** in the DMA and ISR mode (the callback reports the end) and served by `Hash_Task` in the
   POLL mode; the same request and the same callbacks are used in all the modes.
3. `Hash_Set_Update` can be called with any size (also 0 and also not a multiple of the block or the word); the module
   keeps the incomplete block in the FIFO of the hardware and the incomplete word in its own state.
4. `Hash_Set_Finish` pads the message, waits for the digest and writes it to the output buffer in the byte order of the
   standard. After it the peripheral is idle again.
5. `Hash_Get_Context` is allowed between two updates only; after it the peripheral is idle and another message can be
   started. `Hash_Set_Context` restores a context and the incremental calculation continues. A context is valid only
   for the algorithm, the mode and the device it was taken on.
6. `Hash_Set_Abort` stops the calculation and clears the hardware (and the DMA transfer); the key and the message
   data are not kept by the module after the request ends.

---

## Supported families

Every family gets its own story, its own tasks and its own branches `Dev/<Family>` and `Releases/<Family>` cut from this
master.

| Family | Branch | HASH | Status |
|---|---|---|---|
| STM32H5 | `Dev/STM32H5` | `HASH`, SHA-1 and SHA-2 (224 / 256 / 384 / 512) on the lines H523 ... H573, SHA-3 on selected lines, HMAC, DMA, suspend / resume; STM32H503: SHA-1, SHA-224, SHA-256 | planned (first) |
| STM32U5 | `Dev/STM32U5` | `HASH` on the lines that have it | planned |
| STM32H7 | `Dev/STM32H7` | `HASH` (MD5, SHA-1, SHA-2 224 / 256) on the lines that have it | planned |
| STM32F4, STM32F7 | `Dev/STM32F4`, `Dev/STM32F7` | `HASH` (MD5, SHA-1, and SHA-2 224 / 256 where the device has them) on the crypto lines | planned |
| STM32G4, STM32L4, STM32U3 | `Dev/STM32G4`, `Dev/STM32L4`, `Dev/STM32U3` | device dependent | planned |

A function without a meaning in a family stays in the interface, returns `HASH_REQUEST_ERROR` and suppresses the unused
parameters (for example an algorithm the device does not support, the variable output length of SHAKE on a device
without SHA-3, the whole module on a device without the peripheral).

---

## Public interface in short (proposal)

| Group | Functions |
|---|---|
| Module management | `Hash_Get_ModuleVersion`, `Hash_Init`, `Hash_Deinit`, `Hash_Task`, `Hash_Get_DefaultConfig` |
| Capability and state | `Hash_Get_Capability`, `Hash_Get_DigestSize`, `Hash_Get_State`, `Hash_Get_XferError` |
| One-shot | `Hash_Set_Calculate` |
| Incremental | `Hash_Set_Start`, `Hash_Set_Update`, `Hash_Set_Finish`, `Hash_Set_Abort` |
| Suspend and resume | `Hash_Get_Context`, `Hash_Set_Context` |
| Interrupts | `Hash_Set_IrqPriority`, `Hash_Get_IrqPriority` |

```c
hash_ModuleVersion_t Hash_Get_ModuleVersion  ( void );

hash_RequestState_t  Hash_Init               ( const hash_Config_t * const hashConfig );
hash_RequestState_t  Hash_Deinit             ( void );
void                 Hash_Task               ( void );
hash_RequestState_t  Hash_Get_DefaultConfig  ( hash_Config_t * const hashConfig );

hash_RequestState_t  Hash_Get_Capability     ( hash_Algorithm_t algorithm, hash_FunctionState_t * const supported );
hash_RequestState_t  Hash_Get_DigestSize     ( hash_Algorithm_t algorithm, hash_DataCnt_t * const digestSize );
hash_RequestState_t  Hash_Get_State          ( hash_State_t * const hashState );
hash_RequestState_t  Hash_Get_XferError      ( hash_XferError_t * const xferError );

hash_RequestState_t  Hash_Set_Calculate      ( const hash_Request_t * const request );

hash_RequestState_t  Hash_Set_Start          ( const hash_StartConfig_t * const startConfig );
hash_RequestState_t  Hash_Set_Update         ( const hash_Data_t * const data, hash_DataCnt_t dataSize );
hash_RequestState_t  Hash_Set_Finish         ( hash_Data_t * const digest, hash_DataCnt_t digestSize );
hash_RequestState_t  Hash_Set_Abort          ( void );

hash_RequestState_t  Hash_Get_Context        ( hash_Context_t * const context );
hash_RequestState_t  Hash_Set_Context        ( const hash_Context_t * const context );
```

Every function returns `HASH_REQUEST_OK` / `HASH_REQUEST_ERROR` and checks its parameters and the state of the module
before it touches a register.

| Type | Meaning |
|---|---|
| `hash_Config_t` | Transfer mode (`HASH_XFER_MODE_POLL` / `ISR` / `DMA`), DMA channel and priority, interrupt priority, callbacks (complete, error) |
| `hash_Request_t` | Algorithm, mode (hash / HMAC), key and its size, input buffer and size, digest buffer and size (for SHAKE the requested length) |
| `hash_StartConfig_t` | Algorithm, mode, key and its size - the part of the request without data |
| `hash_Context_t` | Opaque storage of a suspended calculation, `HASH_CONTEXT_SIZE` bytes, allocated by the application |
| `hash_State_t` | `HASH_STATE_IDLE`, `HASH_STATE_BUSY`, `HASH_STATE_ERROR` |
| `hash_XferError_t` | DMA error, input overrun, a request in the wrong state (bit mask) |

---

## Usage

### SHA-256 of a buffer

```c
#include "Hash_Port.h"

static hash_Data_t digest[ 32u ];
static volatile hash_FlagState_t digestReady = HASH_FLAG_INACTIVE;

static void App_HashDone( void )
{
    digestReady = HASH_FLAG_ACTIVE;
}

hash_Config_t hashConfig;

(void)Hash_Get_DefaultConfig( &hashConfig );
hashConfig.XferMode         = HASH_XFER_MODE_DMA;
hashConfig.CompleteCallback = App_HashDone;
(void)Hash_Init( &hashConfig );

const hash_Request_t request =
{
    .Algorithm  = HASH_ALGO_SHA2_256,
    .Mode       = HASH_MODE_HASH,
    .Input      = message,
    .InputSize  = messageSize,
    .Digest     = digest,
    .DigestSize = sizeof( digest ),
};

(void)Hash_Set_Calculate( &request );
```

### HMAC of a stream

```c
const hash_StartConfig_t startConfig =
{
    .Algorithm = HASH_ALGO_SHA2_256,
    .Mode      = HASH_MODE_HMAC,
    .Key       = secretKey,
    .KeySize   = secretKeySize,
};

(void)Hash_Set_Start( &startConfig );
(void)Hash_Set_Update( header, headerSize );
(void)Hash_Set_Update( payload, payloadSize );
(void)Hash_Set_Finish( mac, sizeof( mac ) );        /* the callback reports the end in the ISR / DMA mode */
```

### Short digest in the middle of a long calculation

```c
static hash_Context_t imageContext;

(void)Hash_Get_Context( &imageContext );            /* the image calculation is saved, the peripheral is idle */

/* ... another message: Hash_Set_Calculate( ... ) ... */

(void)Hash_Set_Context( &imageContext );            /* the image calculation continues */
(void)Hash_Set_Update( nextImageBlock, blockSize );
```

---

## Behaviour and limits

- **Word access only.** The hardware accepts 32-bit words in its FIFO; the module sends the incomplete last word with
  the number of valid bits and never writes bytes or half-words. A buffer in the flash (the image) is read by the DMA as words,
  the alignment is handled by the module.
- **Digest byte order.** The digest is written as a byte array in the order of the standard (big-endian words of the
  specification), independent of the endianness of the CPU.
- **Cache and DMA.** A buffer written by the CPU and read by the DMA must be visible to the DMA (non-cacheable memory or
  a cache clean by the application on the families with a data cache).
- **One peripheral.** Only one calculation runs at a time; the second request returns an error until the first one
  ends (or is suspended with `Hash_Get_Context`). The module is not re-entrant from an interrupt while a `Hash_Set_*` call of
  the same message is running.
- **Time.** A SHA-256 block takes tens of clock cycles; the throughput is limited by the bus and the DMA, not by the
  hash core. A very large message is split by the module into transfers that fit the DMA counter.
- **Secrets.** The key is written to the input FIFO and is not kept by the module; the application clears its copy.
  The peripheral has no side-channel protection (the Saes / Pka modules offer it for the AES and the public-key operations).
- **Not part of the first version:** the hash of a message in an external memory-mapped memory without the DMA, the
  software fall-back of an algorithm the device does not have, the key derivation functions.

---

## Dependencies

- **Rcc** - peripheral clock and reset
- **Nvic** - interrupt of the peripheral
- **Gpdma** - DMA transfers of the input data
- **RAL (Register Abstraction Layer)** - used internally to access the registers

All mandatory RCC, NVIC and DMA configurations are handled internally.

---

## Testing

- **Unit tests** (host, Unity + CMock + RegMem): the packing of the bytes into words for all alignments and lengths
  (0, 1, 3, 4, 63, 64, 65 ...), the number of valid bits of the last word, the rejected requests (algorithm not supported, buffers,
  the busy state), the order of the digest bytes, the context save and restore, the DMA / ISR / POLL flow with the
  callbacks, the abort.
- **Integration tests** (target, probe-rs): the digests of the standard test vectors (empty message, "abc", the long
  message of one million "a") for every algorithm of the device, the HMAC test vectors (RFC 2202 / 4231), the DMA
  hashing of a flash area, the suspend and resume against a calculation without the interruption.

---

## Interface conventions

The module follows the common rules of the MCAL layer, so that it behaves like the other modules:

- **Lists instead of free members.** Everything that the hardware restricts (the pins, the kernel clock sources, the DMA
  channels, the triggers and the other selectable sources) is a `typedef enum` list with exactly the items that are valid
  for the device line; a pin is an item `HASH_<SIGNAL>_PIN_<INSTANCE>_P<port><pin>` and there is an `*_UNUSED` item. A choice
  that is not in the list cannot be written.
- **Own peripheral only.** The module calls only the registers / LL functions of its own peripheral. The clocks, the
  interrupts, the pins, the DMA and the EXTI lines go through the API of the Rcc, Nvic, Gpio, Gpdma and Exti modules; a
  missing function is added to that module, it is not bypassed.
- **Init verifies itself.** `Hash_Init` checks the result at the end; when it is not as required, the module is
  deinitialized and an error is returned. The waiting for the hardware is a loop on the register state with a timeout,
  never a blind delay.
- **Transfer modes.** Where the module moves data, the POLL (served by `Hash_Task`), ISR and DMA modes have the same
  configuration structure, the same request and the same callbacks (error, half transfer, transfer complete).
- **Flags and states are enums of the module** (`hash_FunctionState_t`, `hash_FlagState_t`), the limits and the constants are
  named, there are no magic numbers in the interface.
- **Unsupported functions stay.** A function without a meaning in a family keeps its signature, suppresses the unused
  parameters and returns `HASH_REQUEST_ERROR`.
- **Documentation.** Every function and type has a Doxygen description, the main header has the `\defgroup`.

---

## Repository layout and branches

The master holds this README and the license. The family branches (`Dev/<Family>`, `Releases/<Family>`) hold:

| Path | Content |
|---|---|
| `README.md` | README of the family: the instances of the device, specifics, errata, status |
| `Hash_Port.h`, `Hash_Types.h` | Public interface (identical in all families) |
| `Hash*.c`, `Hash.h` | Implementation of the family |
| `CMakeLists.txt` | Library `Hash_Lib` of the EmBi platform |
| `Tests/UnitTests` | Unit tests (Unity + CMock + RegMem) |
| `Tests/IntegrationTests` | Integration tests on the target (probe-rs) |

A change of the public interface is made in all families.

---

## CMake integration

```cmake
target_link_libraries( User_Lib PRIVATE Hash_Lib )
```

1. Link `Hash_Lib` to your CMake library.
2. Include `Hash_Port.h` in your project.
3. Configure the module as needed for your hardware.

---

## License

This project is licensed under the **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.

You are free to use, modify, and share this work for **non-commercial purposes**, provided appropriate credit is given.

See [LICENSE.md](LICENSE.md) for full terms or visit [creativecommons.org/licenses/by-nc/4.0](https://creativecommons.org/licenses/by-nc/4.0/).

---

## Authors

- **Mr.Nobody** - [embedbits.com](https://embedbits.com)

Contributions are welcome! Please open a pull request.
