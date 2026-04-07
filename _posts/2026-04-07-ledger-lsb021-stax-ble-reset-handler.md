---
layout: post
title: "reset_handler as Input: Hard Brick & Code Execution on Ledger Stax"
lang: en
category: en
post_id: ledger-lsb021-stax-ble-reset-handler
---

## Background

I vaguely remember seeing some marketing material from a hardware-wallet recovery or forensics company about three years ago, somewhere in a fairly obscure corner of the internet. I do not remember the details anymore, but my impression was that there were companies doing this kind of work professionally, targeting mainstream wallets such as Ledger and Trezor. My guess was that they were relying on vulnerabilities in early boot stages, or on debug-like interfaces.

When I later tried to find those pages again, I could no longer locate the exact ones I had seen. But I did find a lot of related material, including discussion around Ledger Recover. That made me wonder whether some issue in the implementation of that recovery service had ever been found and used in practice (Unfortunately, my research did not give me a real look into the implementation of that feature). Ledger Recover itself has always been controversial. On Bitcoin forums, threads that start as “which hardware wallet should I buy?” or “should I switch wallets?” often end up circling back to that topic. To me, this reflects a recurring tension in the crypto ecosystem: once you try to make a product usable by a broad audience, you often have to make tradeoffs between absolute decentralization and real-world usability.

During that research, I also became increasingly aware of how strong Ledger’s own research team (donjon) is in hardware security, boot chains, and related areas. Especially in the hardware-wallet space, they are hard to beat. Many public wallet-breaking stories against other vendors were done by their team. That alone made their devices an interesting target to study. On top of that, the [Hall of Fame](https://donjon.ledger.com/hall-of-fame/) had been empty for about three years, at least from what I saw at the time, which made me even more curious about how far Ledger had pushed the security boundary.

## Target

At the time, I was looking at the Ledger Stax. One reason it looked interesting was that it supported Bluetooth and NFC, which naturally gives it a larger attack surface than a USB-only device. Architecturally, the outermost layer of the wallet is an MCU, while the critical logic lives in the Secure Element. Older wallets sometimes relied more heavily on the MCU alone, but modern hardware wallets mostly follow this MCU + SE model. Ledger takes the SE side further than many others: not only signing and private-key-related operations, but also the main system, UI, and apps live on the SE side. The MCU mostly handles peripherals such as the screen, touch, USB, and Bluetooth.

For some hardware wallets, the entry point for analysis is not that high. Trezor, for example, is fully open source, and firmware images for different versions are relatively easy to obtain. That is friendly to external researchers. Ledger Stax was a different story. First, Ledger does not provide direct firmware downloads. Second, the open-source code is fragmented: the desktop client is open source, and you can find some wallet-side MCU-related code, but it is mostly for older devices or older versions. There are also scattered snippets related to the Secure Element. None of this is enough to reconstruct the whole system, but it can still provide useful hints during reverse engineering.

As a side note, I do not think the openness of hardware wallets is a binary issue. [WalletScrutiny](https://walletscrutiny.com/) has done more systematic evaluations around this, looking not only at whether source code is available, but also whether it can be built and whether the build output matches the firmware actually shipped by the vendor. The ideal state is clear: source code is available, it builds, and the resulting binary matches the official firmware. In reality, most products do not reach that bar. Common cases are: closed source, partially open source, source code without build instructions, or source code that can be built but does not match the firmware that users actually run.

In general, security should not be built on obscurity. Black-box design does not make something secure; it only raises the cost of analysis for a while. When the target is valuable enough, someone will eventually find a way to get the material they need, whether that is source code, decrypted firmware, or other internal artifacts, and then look for vulnerabilities there. Early iPhone boot chains also tried to raise the bar with encrypted black-box components, but eventually people got keys, accessed factory/debug devices, and dumped BootROM and SEP code. Later on, components such as the kernel and iBoot gradually stopped relying on black-box logic as the main security boundary. For high-value targets, obscurity does not make vulnerabilities disappear. It more often means that fewer people can see them, and the people who do may be the ones least likely to disclose them. That said, black-boxing is not useless. For a newly released product, it can raise the cost of analysis and delay attacks long enough to avoid immediate market-moving incidents.

## Attack Surfaces

Back to Ledger. The two natural routes I thought about were the app route and the MCU route. The app route would mean looking for a bug in an app, or directly trying to trigger something on the Secure Element side, and seeing whether that could open a path into the SE. Ledger, however, has strong control over that path. In a way, it feels a bit like App Store code review. The human and process factors make realistic testing on that route quite difficult.

That made the MCU route more practical: the MCU is the component exposing io surfaces to the outside world. But the MCU side was also heavily black-boxed. The wallet can be updated, but the firmware itself is not directly available. For example, when updating through Ledger Live, the Secure Element establishes an encrypted channel directly with Ledger’s backend server. The server sends encrypted APDUs to the device; the SE can decrypt the update data, but the outside world sees very little. On smart phones, I had seen workflows where the server provides encrypted firmware and the device-side TEE decrypts it during the update process. Ledger’s p2p encrypted delivery model goes more further.

The key observation was that a long press on the device button could put the MCU into bootloader mode. In that state, many normal security properties were not enabled: the encrypted channel between the Secure Element and the server was not active, and Bluetooth communication need no authentication. In other words, anyone who could communicate with the device in that recovery/bootloader state could send messages to it. Ledger Live’s firmware recovery flow also used a plaintext protocol at this stage, so a USB capture was enough to recover the details of the communication.

## Protocol Analysis

The next step was to understand the USB and Bluetooth protocol details, then write a small packet-sending script by hand to test both interfaces. Understanding the protocol also made it possible to extract the firmware being transferred during recovery.

At this point, I found it useful to think of the communication in three layers. The outermost layer is not bootloader semantics; it is just the communication link. The middle layer is Ledger’s APDU transport. The innermost layer is the command set interpreted by the bootloader. Once I split the protocol this way, USB and BLE became much less confusing.

Start with the outer communication entry point. On BLE, the Stax service UUID is `13d63400-2c97-6004-0000-4c6564676572`. Under that service, there are three characteristics with a clear pattern: `0001`, `0002`, and `0003`. Combining packet captures with open-source client code, my understanding is: `0001` is notify and is used for device responses; `0002` is write-with-response; `0003` is write-without-response. The latter has higher throughput, so my test code preferred `0003` and fell back to `0002` if needed.

USB HID and BLE look different on the surface, but the transport layer in the middle is essentially the same. On BLE, it looks like this:

`0x05 | seq(u16be) | (seq==0 ? total_length(u16be) : none) | apdu_bytes...`

On USB HID, the same structure just has a channel in front:

`channel(u16be) | 0x05 | seq(u16be) | (seq==0 ? total_length(u16be) : none) | apdu_bytes...`

Here, `0x05` is not a recovery command. It is an APDU tag. Its job is to split a complete APDU into chunks, number the chunks, send them, and reassemble them on the other side. At the beginning, what Wireshark showed me was just fragmented HID/BLE packets. Only after reassembling them by `tag=0x05` and `seq` could I start talking about what the bootloader was actually receiving.

After reassembly, the payload becomes the bootloader command layer. The full APDU structure is:

`CLA | INS | P1 | P2 | Lc | payload`

I then wrote a Python script to reproduce the recovery flow by hand, which confirmed the format and content of the communication. In the table below, “open-source reference” comes mainly from two places: names used in open-source clients such as `blue-loader-python`, and Ledger’s older open-source [Ledger Blue non-secure MCU firmware](https://github.com/LedgerHQ/blue-nonsecure-firmware). Its README says it is the proxy firmware running on the STM32L4 non-secure MCU and executing commands on behalf of the ST31 Secure Element. I only use it as a reference for naming and design intent.

| Order | My script name | APDU bytes | Approximate name in open-source references | Purpose |
|---|---|---|---|---|
| 1 | `validate_targetid` | `e0040000 04 <target id>` | `INS_VALIDATE_TARGET_ID` / `validateTargetId` | Confirm the target device type |
| 2 | `declare_length` | `e0000001 05 05 <length u32>` | No direct equivalent | Declare the length of the firmware to be written |
| 3 | `declare_startpage` | `e0000000 05 05 <page u32>` | `SECUREINS_SELECT_SEGMENT` / `selectSegment` | Set the base address for subsequent `load` commands |
| 4 | `load` | `e0000000 <Lc> 06 <offset u16> <chunk bytes...>` | `SECUREINS_LOAD` / `loadSegmentChunk` | Write one chunk at a relative offset |
| 5 | `flush` | `e0000000 01 07` | `SECUREINS_FLUSH` / `flushSegment` | Commit the NVM write |
| 6 | `boot` | `e0000000 09 09 <reset_handler> <other_data>` | `SECUREINS_BOOT` / `boot` / `run` | Store and use the boot entry point |

This table is essentially the call chain in my script: first `validate_targetid`, then `declare_length`, then `declare_startpage` selecting `0x0800a000`, followed by `load` in `0x80`-byte chunks. Then another `declare_startpage` switches to `0x0801a000`, and the remaining chunks are loaded. After all chunks are written, the flow sends `flush`, and finally `boot`.

There are two details worth being careful about. First, `declare_startpage` is just the name I gave it in my script. Looking at the Ledger Blue code and `blue-loader-python`, the more accurate semantic name is probably `selectSegment`: it sets `load_address`, and the later `load` commands only carry a relative offset. The real write address is `load_address + offset`.

Second, `declare_length` should not be force-mapped to a Ledger Blue name. It also uses subcommand `0x05`, but the APDU header uses `P2=1`, while `selectSegment` uses `P2=0`. I did not find a direct equivalent for this command in the old Ledger Blue source, so I treat it as a command observed in the Stax recovery flow through black-box testing.

At this point, the final `boot` command immediately stood out to me. It was not simply telling the device “you can boot now”; it also carried a host-provided `reset_handler` address. In the Ledger Blue source, the corresponding field is called `appmain`.

## Firmware Comparison

Since I had obtained an MCU firmware dump, the obvious question is: why not just compare the code and pin down the logic directly? The main reason is that this dump looked more like the runtime image used during normal system boot. I was not sure whether it was the exact code running in bootloader mode. In this runtime/flashback path, I could indeed see that some APDUs were forwarded to the Secure Element through `SE_iso_exchange_apdu(...)`, and I could also see local handling of a version query returning `5.26.1`. But that does not mean the full recovery bootloader state machine for `load` / `flush` / `boot` lives in this image. So this firmware was useful for understanding the USB/Bluetooth communication layer, but for analyzing the custom bootloader flashing commands and their validation behavior, the work was still mostly black-box.

For example, the following is simplified pseudocode I recovered from the MCU runtime path. It shows USB/APDU handling and the SE bridge, but not the full recovery bootloader flashing state machine:

```c
static uint16_t handle_flashback_apdu(uint16_t rx_len) {
    // E0 class path
    if (G_io_seproxyhal_buffer[0] == 0xE0) {
        if (rx_len > 3 && memcmp(&G_io_seproxyhal_buffer[1], byte_8019E34, 3) == 0) {
            // Return version "5.26.1" + SW=9000
            G_io_seproxyhal_buffer[0] = 5;
            G_io_seproxyhal_buffer[1] = 0;
            G_io_seproxyhal_buffer[2] = 0;
            G_io_seproxyhal_buffer[3] = 0;
            G_io_seproxyhal_buffer[4] = 6;
            memcpy(&G_io_seproxyhal_buffer[5], "5.26.1", 6);
            G_io_seproxyhal_buffer[11] = 0x90;
            G_io_seproxyhal_buffer[12] = 0x00;
            return 13;
        }
        return SE_iso_exchange_apdu(G_io_seproxyhal_buffer, rx_len, 302);
    }
}
```

## Vulnerability

Back to the final `boot` command. It passes an MCU address, and the `0x08...` address clearly sits in the MCU code address space, semantically matching an application entry point / reset handler. More importantly, this value is provided by the host; it is not derived internally by the device. Once that is true, the problem becomes much narrower: if the system already knows what the valid entry point should be, it should not need the host to provide it. Conversely, if validation here is not strict enough, the host can hijack the program counter.

The Ledger Blue code helps explain why this matters: the `boot` command writes the host-provided entry point into a persistent boot configuration and uses it on a later boot:

```c
case SECUREINS_BOOT: {
            if (rx != 1+4) {
              sw = 0x6700; goto error;
            }

            union {
             bootloader_configuration_t ramconf;
             unsigned char page_remaining[NVM_PAGE_SIZE_B];
            } bootpage;
            memset(&bootpage, 0, NVM_PAGE_SIZE_B);

            // write the address of the main
            bootpage.ramconf.appmain = (appmain_t)U4BE(G_io_apdu_buffer, 6);
            // to be done in called code // ramconf.vtor = (appmain_t)U4BE(G_io_apdu_buffer, 6+4);

            // update the crc value
            bootpage.ramconf.crc = cx_crc16(&bootpage.ramconf.appmain, sizeof(appmain_t));
            // ensure page always filled with zeros, as per code signature generation (even if tearing during page)
            nvm_write(&N_bootloader_configuration, &bootpage, NVM_PAGE_SIZE_B);

            // ensure flushing the boot configuration into nvram
            nvm_write_flush();

            // from now on, the application can boot, boot now
            flags |= IO_RESET_AFTER_REPLIED;

            ///BEGIN WIPE STATE
            // invalidate the IV, make sure nothing can be validated after that
            os_memset(&(iv[0]), 0xFF, sizeof(iv));
            state = STATE_ID;
            ///END WIPE STATE
            break;
          }
```

## Impact

My PoC was straightforward: keep the rest of the flashing flow unchanged, and modify only this boot entry address. The device was bricked. On every boot, it jumped to the wrong PC, and there was no later opportunity to overwrite the value again. 

One prank scenario for exploiting this vulnerability involves devices kept behind a counter or still sitting on shelves inside their original packaging. By simply squeezing the box—thereby holding down the power button—an attacker can force the device into bootloader mode; subsequently, by sending specific packets via BLE, they can brick the device.

Turning this into a reliable code-execution exploit would still be challenging. The hard part is not a particularly strong mitigation environment; the hard part is that if you get it wrong, you do not get another try. In the MCU + SE architecture, compromising the MCU is also only the first step toward compromising the wallet as a whole. To actually get private keys, you would still need to break the SE. But controlling the MCU is still meaningful: much like a renderer RCE without a sandbox escape can still produce UXSS-like impact, MCU control in some other wallets can be enough to tamper with what the user sees or signs.

## Disclosure

I reported this vulnerability to Ledger around January 2025. They fixed it quickly and added me to the Hall of Fame, but the public technical disclosure took much longer. That is understandable: these devices are not like phones receiving OTA updates. Connectivity is lower, upgrade cadence is slower, and Ledger had to validate the fix and prepare firmware across multiple product lines. The window naturally became long. Around January 2026, Ledger published the details in [LSB-021](https://donjon.ledger.com/lsb/021/). 
