import Foundation

// MARK: - 実験用の「機械」の部品
//
// Android エミュレータと同じ virtio-net（仮想 LAN カード）を、そのまま使う。
// 本物のエミュレータでは Linux（ゲスト）がこのカードを動かすが、この実験アプリでは
// ゲストの代わりに、Swift で書いた小さな「ドライバ」と「TCP/IP」（GuestStack）が動かす。
//
//   ブラウザ（WKWebView）→ HTTPClient → GuestStack（TCP/IP）→ VirtioNetDriver
//     → VirtioNet（仮想 LAN カード・エミュレータと同じもの）→ UserNet（小さなルーター）→ iPad の通信

/// ゲストの RAM（virtio のキューと、フレームの入れ物を置く）。アドレスは 0x4000_0000 から
final class GuestRAM: @unchecked Sendable {
    let base: UInt64 = 0x4000_0000
    let size: UInt64
    let words: UnsafeMutablePointer<UInt64>
    private var next: UInt64 = 0
    init(megabytes: Int) {
        size = UInt64(megabytes) << 20
        words = .allocate(capacity: Int(size / 8))
        words.initialize(repeating: 0, count: Int(size / 8))
    }
    deinit { words.deallocate() }
    /// 置き場所をもらう（align の倍数に揃える）。戻り値はゲストの物理アドレス
    func alloc(_ count: Int, align: UInt64 = 16) -> UInt64 {
        next = (next + align - 1) / align * align
        let a = base + next
        next += UInt64(count)
        precondition(next <= size, "GuestRAM が足りません")
        return a
    }
    func pointer(_ pa: UInt64) -> UnsafeMutableRawPointer { UnsafeMutableRawPointer(words) + Int(pa - base) }
    func load16(_ pa: UInt64) -> UInt16 { pointer(pa).loadUnaligned(as: UInt16.self) }
    func load32(_ pa: UInt64) -> UInt32 { pointer(pa).loadUnaligned(as: UInt32.self) }
    func store16(_ pa: UInt64, _ v: UInt16) { pointer(pa).storeBytes(of: v, as: UInt16.self) }
    func store32(_ pa: UInt64, _ v: UInt32) { pointer(pa).storeBytes(of: v, as: UInt32.self) }
    func store64(_ pa: UInt64, _ v: UInt64) { pointer(pa).storeBytes(of: v, as: UInt64.self) }
}

/// 周辺機器（エミュレータの MMIODevice と同じ形）
protocol MMIODevice: AnyObject {
    var base: UInt64 { get }
    var size: UInt64 { get }
    var irq: Int { get }
    var interruptLine: Bool { get }
    func read(_ offset: UInt64, size: Int) -> UInt64
    func write(_ offset: UInt64, size: Int, value: UInt64)
}

// MARK: - virtio-mmio のネットワーク（Linux では eth0 になる）
//
// キューは 2 つ: 0 = 受け取り用（OS が空の入れ物を並べておく）、1 = 送り出し用。
// 1 つの入れ物 = [virtio_net_hdr 10 バイト] [イーサネットのフレーム]（古い形 = legacy、MRG_RXBUF なし）
// 送り出されたフレームは onTransmit に渡す。外から届いたフレームは receive(_:) で受け取り、
// OS が並べた入れ物に書き込む（入れ物が無ければ、来るまで取っておく）。
// receive はほかのスレッドから呼んでもよい（鍵で守る）。入れ物に書くのは CPU の側（interruptLine を見るとき）
final class VirtioNet: MMIODevice, @unchecked Sendable {
    let base: UInt64
    let size: UInt64 = 0x200
    let irq: Int
    let legacy: Bool
    /// この機械の MAC アドレス（QEMU と同じ 52:54:00:12:34:56）
    let mac: [UInt8] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56]

    private let ramWords: UnsafeMutablePointer<UInt64>
    private let ramBase: UInt64
    private let ramSize: UInt64
    /// RAM に書き込んだ範囲を CPU に知らせる（命令のデコード結果を捨ててもらうため）
    var onDMAWrite: ((UInt64, Int) -> Void)?
    /// OS が送り出したフレーム（ヘッダを除いたイーサネットのフレーム）
    var onTransmit: (([UInt8]) -> Void)?

    private struct Queue {
        var num: UInt32 = 0
        var ready: UInt32 = 0
        var desc: UInt64 = 0
        var avail: UInt64 = 0
        var used: UInt64 = 0
        var lastAvail: UInt16 = 0
        var align: UInt32 = 4096
        var pfn: UInt32 = 0
    }
    private var queues = [Queue(), Queue()]
    private var status: UInt32 = 0
    private var deviceFeaturesSel: UInt32 = 0
    private var driverFeaturesSel: UInt32 = 0
    private var driverFeatures: UInt64 = 0
    private var queueSel: UInt32 = 0
    private var interruptStatus: UInt32 = 0
    private var guestPageSize: UInt32 = 4096

    /// まだ OS に渡していない受け取ったフレーム
    private var pending: [[UInt8]] = []
    private let lock = NSLock()
    private var hasPending = false
    static let queueMax: UInt32 = 256
    static let headerSize = 10
    /// 統計
    private(set) var sentFrames = 0
    private(set) var receivedFrames = 0
    private(set) var droppedFrames = 0

    init(base: UInt64, irq: Int, memory: GuestRAM, legacy: Bool = true) {
        self.base = base
        self.irq = irq
        self.legacy = legacy
        ramWords = memory.words
        ramBase = memory.base
        ramSize = memory.size
    }

    var interruptLine: Bool {
        if hasPending { deliverPending() }
        return interruptStatus != 0
    }

    /// 外から届いたフレームを受け取る（どのスレッドからでもよい）
    func receive(_ frame: [UInt8]) {
        lock.lock()
        if pending.count >= 512 { pending.removeFirst(); droppedFrames += 1 }
        pending.append(frame)
        hasPending = true
        lock.unlock()
    }

    /// 持っている機能: MAC（bit5）。バージョン 2 なら VERSION_1（bit32）も
    private var deviceFeatures: UInt64 { (legacy ? 0 : 1 << 32) | (1 << 5) }

    func reset() {
        status = 0
        deviceFeaturesSel = 0
        driverFeaturesSel = 0
        driverFeatures = 0
        queueSel = 0
        interruptStatus = 0
        guestPageSize = 4096
        queues = [Queue(), Queue()]
    }

    func read(_ offset: UInt64, size width: Int) -> UInt64 {
        if offset >= 0x100 {
            // 設定領域: 先頭 6 バイトが MAC アドレス
            var r: UInt64 = 0
            for k in 0..<width {
                let i = Int(offset - 0x100) + k
                if i < 6 { r |= UInt64(mac[i]) << UInt64(8 * k) }
            }
            return r
        }
        let qs = Int(queueSel)
        switch offset {
        case 0x000: return 0x7472_6976
        case 0x004: return legacy ? 1 : 2
        case 0x008: return 1                                   // デバイスの種類: 1 = ネットワーク
        case 0x00C: return 0x554D_4551
        case 0x010: return deviceFeaturesSel < 2 ? (deviceFeatures >> UInt64(32 * deviceFeaturesSel)) & 0xFFFF_FFFF : 0
        case 0x034: return qs < 2 ? UInt64(VirtioNet.queueMax) : 0
        case 0x040: return legacy && qs < 2 ? UInt64(queues[qs].pfn) : 0
        case 0x044: return qs < 2 ? UInt64(queues[qs].ready) : 0
        case 0x060: return UInt64(interruptStatus)
        case 0x070: return UInt64(status)
        default: return 0
        }
    }

    func write(_ offset: UInt64, size width: Int, value: UInt64) {
        let v = UInt32(truncatingIfNeeded: value)
        let qs = Int(queueSel)
        let ok = qs < 2
        switch offset {
        case 0x014: deviceFeaturesSel = v
        case 0x020:
            if driverFeaturesSel < 2 {
                let shift = UInt64(32 * driverFeaturesSel)
                driverFeatures = (driverFeatures & ~(0xFFFF_FFFF << shift)) | (UInt64(v) << shift)
            }
        case 0x024: driverFeaturesSel = v
        case 0x028: if legacy { guestPageSize = v == 0 ? 4096 : v }
        case 0x030: queueSel = v
        case 0x038: if ok { queues[qs].num = min(v, VirtioNet.queueMax) }
        case 0x03C: if legacy && ok { queues[qs].align = v == 0 ? 4096 : v }
        case 0x040: if legacy && ok { setLegacyQueue(qs, pfn: v) }
        case 0x044: if ok { queues[qs].ready = v & 1 }
        case 0x050:                                              // QueueNotify
            if v == 1 { transmit() } else if v == 0 { deliverPending() }
        case 0x064: interruptStatus &= ~v
        case 0x070: if v == 0 { reset() } else { status = v }
        case 0x080: if ok { queues[qs].desc = setLow(queues[qs].desc, v) }
        case 0x084: if ok { queues[qs].desc = setHigh(queues[qs].desc, v) }
        case 0x090: if ok { queues[qs].avail = setLow(queues[qs].avail, v) }
        case 0x094: if ok { queues[qs].avail = setHigh(queues[qs].avail, v) }
        case 0x0A0: if ok { queues[qs].used = setLow(queues[qs].used, v) }
        case 0x0A4: if ok { queues[qs].used = setHigh(queues[qs].used, v) }
        default: break
        }
    }

    private func setLegacyQueue(_ i: Int, pfn: UInt32) {
        queues[i].pfn = pfn
        if pfn == 0 { queues[i].ready = 0; queues[i].lastAvail = 0; return }
        let num = UInt64(queues[i].num == 0 ? VirtioNet.queueMax : queues[i].num)
        let desc = UInt64(pfn) * UInt64(guestPageSize)
        let avail = desc + 16 * num
        let align = UInt64(queues[i].align)
        let availEnd = avail + 4 + 2 * num + 2
        queues[i].desc = desc
        queues[i].avail = avail
        queues[i].used = (availEnd + align - 1) / align * align
        queues[i].lastAvail = 0
        queues[i].ready = 1
    }

    private func setLow(_ x: UInt64, _ v: UInt32) -> UInt64 { (x & 0xFFFF_FFFF_0000_0000) | UInt64(v) }
    private func setHigh(_ x: UInt64, _ v: UInt32) -> UInt64 { (x & 0xFFFF_FFFF) | (UInt64(v) << 32) }

    private func ramPointer(_ pa: UInt64, _ count: Int) -> UnsafeMutableRawPointer? {
        let off = pa &- ramBase
        guard pa >= ramBase, off <= ramSize, UInt64(count) <= ramSize - off else { return nil }
        return UnsafeMutableRawPointer(ramWords) + Int(off)
    }
    private func load16(_ pa: UInt64) -> UInt16 { ramPointer(pa, 2)?.loadUnaligned(as: UInt16.self) ?? 0 }
    private func load32(_ pa: UInt64) -> UInt32 { ramPointer(pa, 4)?.loadUnaligned(as: UInt32.self) ?? 0 }
    private func load64(_ pa: UInt64) -> UInt64 { ramPointer(pa, 8)?.loadUnaligned(as: UInt64.self) ?? 0 }
    private func store16(_ pa: UInt64, _ v: UInt16) { ramPointer(pa, 2)?.storeBytes(of: v, toByteOffset: 0, as: UInt16.self) }
    private func store32(_ pa: UInt64, _ v: UInt32) { ramPointer(pa, 4)?.storeBytes(of: v, toByteOffset: 0, as: UInt32.self) }

    /// 記述子のつながり: (アドレス, 長さ, 書き込み用か)
    private func chain(_ q: Queue, head: UInt16) -> [(UInt64, Int, Bool)] {
        var out: [(UInt64, Int, Bool)] = []
        var i = head
        let num = UInt16(q.num == 0 ? VirtioNet.queueMax : q.num)
        for _ in 0..<Int(num) {
            let d = q.desc + 16 * UInt64(i % num)
            let flags = load16(d + 12)
            out.append((load64(d), Int(load32(d + 8)), flags & 2 != 0))
            if flags & 1 == 0 { break }
            i = load16(d + 14)
        }
        return out
    }

    private func pushUsed(_ i: Int, head: UInt16, len: Int) {
        let q = queues[i]
        let num = UInt16(q.num == 0 ? VirtioNet.queueMax : q.num)
        let usedIdx = load16(q.used + 2)
        let slot = q.used + 4 + 8 * UInt64(usedIdx % num)
        store32(slot, UInt32(head))
        store32(slot + 4, UInt32(len))
        store16(q.used + 2, usedIdx &+ 1)
    }

    /// 送り出し用のキューに並んだフレームを取り出して onTransmit に渡す
    private func transmit() {
        let qi = 1
        guard queues[qi].ready != 0 else { return }
        let num = UInt16(queues[qi].num == 0 ? VirtioNet.queueMax : queues[qi].num)
        let availIdx = load16(queues[qi].avail + 2)
        var did = false
        var guardCount = 0
        while queues[qi].lastAvail != availIdx && guardCount < Int(num) * 2 {
            guardCount += 1
            let head = load16(queues[qi].avail + 4 + 2 * UInt64(queues[qi].lastAvail % num))
            var bytes: [UInt8] = []
            for (addr, len, writable) in chain(queues[qi], head: head) where !writable {
                guard len > 0, len <= 65536, let p = ramPointer(addr, len) else { continue }
                bytes.append(contentsOf: UnsafeRawBufferPointer(start: p, count: len))
            }
            if bytes.count > VirtioNet.headerSize {
                sentFrames += 1
                onTransmit?(Array(bytes[VirtioNet.headerSize...]))
            }
            pushUsed(qi, head: head, len: 0)
            queues[qi].lastAvail &+= 1
            did = true
        }
        if did { interruptStatus |= 1 }
    }

    /// 取っておいたフレームを、OS が並べた受け取り用の入れ物に書く
    private func deliverPending() {
        let qi = 0
        guard queues[qi].ready != 0 else { return }
        let num = UInt16(queues[qi].num == 0 ? VirtioNet.queueMax : queues[qi].num)
        var did = false
        lock.lock()
        while !pending.isEmpty {
            let availIdx = load16(queues[qi].avail + 2)
            if queues[qi].lastAvail == availIdx { break }       // 入れ物が無い: あとで
            let head = load16(queues[qi].avail + 4 + 2 * UInt64(queues[qi].lastAvail % num))
            let frame = pending.removeFirst()
            // ヘッダ（10 バイトの 0）+ フレームを、入れ物の記述子に順に詰める
            var full = [UInt8](repeating: 0, count: VirtioNet.headerSize)
            full.append(contentsOf: frame)
            var written = 0
            for (addr, len, writable) in chain(queues[qi], head: head) where writable {
                if written >= full.count { break }
                let n = min(len, full.count - written)
                guard n > 0, let p = ramPointer(addr, n) else { continue }
                full.withUnsafeBytes { src in p.copyMemory(from: src.baseAddress! + written, byteCount: n) }
                onDMAWrite?(addr, n)
                written += n
            }
            receivedFrames += 1
            pushUsed(qi, head: head, len: written)
            queues[qi].lastAvail &+= 1
            did = true
        }
        hasPending = !pending.isEmpty
        lock.unlock()
        if did { interruptStatus |= 1 }
    }
}
