---
layout: post
title: "当 reset_handler 变成参数：BLE 触发 Ledger Stax 变砖/代码执行"
lang: cn
category: cn
post_id: ledger-lsb021-stax-ble-reset-handler
---

## 背景

记得最早可能三年前某个时候，我在哪个隐秘的角落看到过做硬件钱包破解的公司宣传。具体细节记不清了，但我印象里有人专门做这类事，针对的目标大概包括 Ledger， Trezor等主流的钱包，估计是利用一些启动阶段的软硬件的漏洞或者是近似debug接口搞的。

后来想起来回头再找的时候，虽然当时的那些页面找不到了，但查到很多其他相关的内容，注意到 Ledger 曾推出过 Recovery 这类服务，我就在想有没有可能是这个服务实现的有漏洞当时被人逮着了呢，遗憾的是我这次分析也没能对这个功能的实现一窥究竟。围绕这个Recovery服务好像争议一直很大，在 bitcoin 论坛里的帖子，很多原本只是讨论“哪家硬件钱包更好”或者“要不要换钱包”，最后都会被带到这个话题上。感觉这也是区块链发展过程中一个反复出现问题的缩影：就是真想把产品做成一个面向大众的时候，很多时候就不得不在“绝对去中心化”和“现实可用性”之间取舍。

我在调研中也逐渐意识到，Ledger 自己的研究团队在硬件安全、启动链等方向上的能力极强，硬件钱包领域无出其右。很多同行钱包破解案例，就是他们做出来的。去分析这样一个优秀团队的作品本来就很有吸引力，再加上近三年的 [Hall of Fame](https://donjon.ledger.com/hall-of-fame/) 无人上榜，这就更让我想看看：Ledger 到底做到了什么程度。

## 目标

我当时看的是最新的 Ledger Stax，觉得它有搞头的一个原因是这款设备支持蓝牙和NFC，攻击面天然比只有 USB 的设备多。钱包最外层是 MCU，关键逻辑放在SE安全芯片里。虽然以前是有单独MCU成事儿的，但今天的硬件钱包应该大都是这种架构了。不过 Ledger SE用的更彻底，不只是把签名，私钥加密之类用安全芯片实现，连主系统、UI、各类 App 都塞进安全芯片侧；MCU 更多承担基本屏幕、触摸、USB、蓝牙这些纯外设的连接和控制。

一些硬件钱包的分析起点其实并不高。比如 Trezor，代码是完全开放的，不同版本的固件也比较容易取得，对外部研究者很友好。但当时看的 Ledger Stax，情况就很麻烦。首先，官方并不提供固件下载；其次，它开源的代码比较零散，比如桌面客户端是开源的，钱包侧能找到一些 MCU 相关代码，但主要是老设备、老版本的代码。另外还有一些和安全芯片相关的零碎片段。这些虽然不足以直接还原全貌，但在逆向过程还是有提示作用的。

说些题外话，感觉硬件钱包的开放成都确实不是很一刀切的选择，WalletScrutiny 做过比较系统的评测，评估内容不只是有没有源码，还包括源码能不能编译、编译出来的结果能不能和官方实际发布的固件对应。最理想的状态当然是：有源码，能编译，而且编译产物和官方固件一致。但现实里，大多数产品都达不到这个标准。常见的情况是：要么完全闭源，要么只开源一部分代码；要么虽然放出了源码，但不说明怎么构建；再往前一步，即便你设法编译出来了，产物也未必和官方发布的固件一致。

一般来说，安全不应该建立在 obscurity 之上。黑盒不等于安全，它只是暂时把分析门槛抬高而已。当目标价值足够高时，总会有人设法拿到那些本来不想让人看到的东西，无论是源码、解密的固件，还是其他内部材料，然后从里面找漏洞。比如早期 iPhone 的启动链也试过通过加密黑盒来抬高门槛，但最终还是有人拿到 key、接触到了工厂调试设备，dump BootROM 和 SEP。再往后，像内核、iBoot 这些东西也逐渐不再依赖黑盒逻辑来维持安全性。所以对高价值目标来说，obscurity 的结果并不是漏洞不存在，而是漏洞更容易掌握在极少数真正的攻击者手里；外部研究人员看不到，也就少了很多撞掉这些漏洞的机会。当然，黑盒也不是毫无作用。尤其新产品刚发布的一段时间里，它确实能提高分析成本，延缓攻击的到来，让市场短期内没有大新闻。

## 攻击思路

说回 ledger，当时比较自然想到的是两条攻击路线，第一条是 App 线：如果某个 App 本身有漏洞或者直接尝试触发安全芯片侧的漏洞，是否能直接打开SE的突破口？但 Ledger 在这条线上做了比较强的管控，某种程度上有点像Appstore的上架审核。人为因素的引入让这条路现实测试难度很高。这样一来，更现实的就是 MCU 作为对外提供输入口的这条线。但 MCU 这边的黑盒化也做得非常彻底，钱包虽然有升级功能，但固件本身拿不到：比如通过 客户端 Ledger Live 给钱包升级时，安全芯片是直接和服务器后台通信建立了加密信道，所以服务器那边发送到设备的都是加密 APDU，安全芯片能解开升级数据，但外界什么都摸不到。手机上见过的顶多是服务器提供加密固件，然后进入设备进行升级服务时候 TEE 去解密固件，但这种下载信道就直接点到点加密的方式还是很厉害的。

但我发现设备长按开关可以让 MCU 进入 bootloader 模式，而且这种状态很多安全特性没有使能，比如安全芯片和服务器的加密信道没有启用，蓝牙通信的身份认证也没有启用，所以任何人都可以直接给钱包发消息。并且这时候 Ledger Live 恢复固件的操作使用的是明文协议，USB 抓包就足以拿到全部通信的细节了。

## 协议分析

接下来就是搞清楚 USB 和蓝牙到底协议细节是怎样的，然后手搓一个发包脚本可以测试不同接口，搞清楚协议也可用来提取恢复时候传输的固件。

此时的的通信协议包可以分成三层，最外面不是 bootloader 语义，而是通信链路；中间是 Ledger 自己的 APDU ；最里面才是 bootloader 真正解释的命令。把这三层拆开以后，USB 和 BLE 其实就没有那么乱了。

先看最外层的通信入口。BLE 这边，Stax 的 service UUID：`13d63400-2c97-6004-0000-4c6564676572`。这个 service 下有三个 characteristic：`0001`、`0002`、`0003`。结合抓包和开源客户端实现，我对它们的理解是：`0001` 是 notify，用来收设备回包；`0002` 是 write-with-response；`0003` 是 write-without-response，吞吐更高，所以我的测试代码里优先用 `0003` 发，没有的话再退回 `0002`。

USB HID 和 BLE 表面上不一样，但中间那层是同构的。BLE 上跑的是：

`0x05 | seq(u16be) | (seq==0 ? total_length(u16be) : none) | apdu_bytes...`

USB HID 上只是前面多了一个 channel：

`channel(u16be) | 0x05 | seq(u16be) | (seq==0 ? total_length(u16be) : none) | apdu_bytes...`

这里的 `0x05` 不是某个恢复命令，而是 APDU tag。它只负责把一条完整 APDU 分片、编号、发送、再在另一端拼回去；一开始从 Wireshark 看到的只是碎片化的 HID/BLE 包，只有先按 `tag=0x05` 和 `seq` 把它们拼回完整 APDU，后面才能讨论 bootloader 到底收到了什么。

拼回 APDU 以后，里面才是 bootloader 的命令层。完整 APDU 结构是：

`CLA | INS | P1 | P2 | Lc | payload`

然后我手搓了python代码复现了这个恢复流程，算是确认了通信的格式和内容。这里表里的“开源参考”主要来自两部分：一部分是 `blue-loader-python` 这种开源客户端里的命名，另一部分是 Ledger 早期开源过的 [Ledger Blue non-secure MCU firmware](https://github.com/LedgerHQ/blue-nonsecure-firmware)。这是 Ledger Blue 的旧实现，不是 Stax/Flex/Nano X 的源码；README 里也说它是替 ST31 Secure Element 执行命令的 proxy firmware，可以当成协议命名和设计思路的参考。

| 顺序 | 我的脚本命名 | APDU bytes | 开源参考中的近似命名 | 作用 |
|---|---|---|---|---|
| 1 | `validate_targetid` | `e0040000 04 <target id>` | `INS_VALIDATE_TARGET_ID` / `validateTargetId` | 确认目标设备类型 |
| 2 | `declare_length` | `e0000001 05 05 <length u32>` | 无直接对应 | 声明待写入固件长度 |
| 3 | `declare_startpage` | `e0000000 05 05 <page u32>` | `SECUREINS_SELECT_SEGMENT` / `selectSegment` | 设置后续 `load` 的基地址 |
| 4 | `load` | `e0000000 <Lc> 06 <offset u16> <chunk bytes...>` | `SECUREINS_LOAD` / `loadSegmentChunk` | 按相对 offset 写入一个 chunk |
| 5 | `flush` | `e0000000 01 07` | `SECUREINS_FLUSH` / `flushSegment` | 提交 NVM 写入 |
| 6 | `boot` | `e0000000 09 09 <reset_handler> <other_data>` | `SECUREINS_BOOT` / `boot` / `run` | 写入并使用启动入口 |


这张表基本就是我脚本里那条调用链：先 `validate_targetid`，再 `declare_length`，然后 `declare_startpage` 选择 `0x0800a000`，按 `0x80 bytes` 一块一块 `load`；接着再 `declare_startpage` 到 `0x0801a000`，继续 `load` 剩下的区域；所有 chunk 写完以后 `flush`，最后 `boot`。

这里有两个地方要特别小心。第一，`declare_startpage` 是我起的名字。从 Ledger Blue 和 `blue-loader-python` 的实现看，更准确的语义其实是 `selectSegment`：它设置的是 `load_address`，后面的 `load` 只带相对 offset，真实写入地址是 `load_address + offset`。

第二，`declare_length` 不应该强行套到 Ledger Blue 的名字上。它虽然也用了子命令号 `0x05`，但 APDU 头里是 `P2=1`，而 `selectSegment` 是 `P2=0`。Ledger Blue 旧源码里我没有看到这条命令的直接对应实现，所以这里最好写成 Stax 恢复流程里黑盒观察到的扩展命令。

分析到这里，我马上注意到最后这个 `boot`：它不是单纯通知设备“可以启动了”，而是把一个主机侧提供的 `reset_handler` 地址也一起传了进去。在 Ledger Blue 源码里，对应字段叫 `appmain`。

## 固件对照

既然都把 MCU 固件拿到了，为什么不直接去对照代码，把这个逻辑搞清楚？主要原因是，这个 dump 出来的 MCU 固件更像是系统正常启动时候使用的 runtime 映像，但它到底是不是 bootloader 模式下真正跑的那份代码，我不是很确定。我在这份 runtime/flashback 路径里确实能看到一些 APDU 会继续转给安全芯片处理，比如 `SE_iso_exchange_apdu(...)`，也能看到它本地处理版本查询并返回 `5.26.1`；但这不等于真正 recovery bootloader 的 `load/flush/boot` 状态机就在这份映像里。所以这个固件更适合帮我理解 USB、蓝牙通信这一级别的问题；但如果是分析 bootloader 自定义的刷机指令到底有哪些、实现上有没有问题，其实基本还是黑盒。

比如下面这段就是我从当前 MCU 的 runtime 路径里逆出来的简化伪代码。它看得见 USB/APDU 处理和 SE bridge，但看不见完整的 recovery bootloader 刷写状态机。

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

## 漏洞点

说回之前最后那条 `boot` 指令，它会传一个 MCU 地址进去，而这个 `0x08` 开头的地址从固件里看，也确实reset_handler函数。这个值是主机传过去的，不是设备自己内部推导出来的。只要这一点成立，问题就会一下子收敛起来：如果系统本来就知道哪个地址才是合法的，那它其实没必要让我来传；反过来说，只要这里的校验不够严格，就可以直接控PC。

参考 Ledger Blue 的代码，它能解释为什么 `boot` 命令会把主机传入的入口地址写进一个持久化配置里，并在后续启动时使用：

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

## 影响

我的 poc 也很直接，保持其余刷机流程不变，只改这个启动地址，然后我的设备就变砖了……每次开机都会跳到这个错误的 PC 执行，但后面就没有机会重新覆写了。一个恶作剧的应用场景是，比如对于柜台里的设备，或者货架还在包装盒子里的设备，可以很容易挤压盒子，通过长时间按开关就进 bootloader 触发这个漏洞，然后通过 BLE 发包变砖哈。

这个漏洞如果写代码执行的 exploit 还是很有挑战的，倒不是利用环境有多么苛刻的 mitigation，关键是一旦错了，没机会再试。不过MCU + SE 的架构下，攻破硬件钱包，拿到 MCU 代码执行肯定只是第一步，只要继续搞定 SE 才真的能拿到私钥。但有时候搞定MCU，就像搞定render RCE 后就算没有 sandbox escape，至少也有个 UXSS 的效果，比如很多其他钱包利用MCU就可以篡改要签名的内容之类的。

## 披露

这个漏洞大概是在 2025 年 1 月提交给 Ledger 的，他们修得很快，并把我加入了名人堂，但公开漏洞细节的时间要晚得多，原因也好理解这类设备和手机 OTA 不一样，联网率低，升级节奏慢，要确保多个产品线都验证通过、固件都准备好，时间窗口自然会拉得很长。一直到 2026 年 1 月左右，他们通过 [LSB-021](https://donjon.ledger.com/lsb/021/) 公开细节。
