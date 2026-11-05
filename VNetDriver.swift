import Foundation

// MARK: - ゲスト側の virtio-net ドライバ（Linux の virtio_net ドライバの代わり）
//
// 仮想 LAN カード（VirtioNet）のレジスタを、Linux と同じ順番で読み書きして使えるようにする。
// ・キューは 2 つ: 0 = 受け取り用、1 = 送り出し用（古い形 = legacy の virtio-mmio）
// ・受け取り用には、あらかじめ空の入れ物（2KB）を並べておく。カードが届いたフレームを書いてくれる
// ・送るときは、入れ物に [ヘッダ 10 バイト][フレーム] を書いて、avail リングに並べて「通知」する
// すべて 1 本のキュー（VNetMachine.queue）の上で呼ぶこと
final class VirtioNetDriver: @unchecked Sendable {
    let dev: VirtioNet
    let ram: GuestRAM
    let qsize = 64
    let bufSize = 2048
    private(set) var mac: [UInt8] = []

    private struct Ring {
        var desc: UInt64 = 0, avail: UInt64 = 0, used: UInt64 = 0
        var bufs: [UInt64] = []
        var lastUsed: UInt16 = 0
        var availIdx: UInt16 = 0
    }
    private var rx = Ring()
    private var tx = Ring()
    private var txFree: [Int] = []
    /// まだ入れ物が空かず送れていないフレーム
    private var txWaiting: [[UInt8]] = []

    /// 届いたフレーム（ヘッダを除いたイーサネットのフレーム）
    var onReceive: (([UInt8]) -> Void)?
    private(set) var sent = 0, received = 0

    init(dev: VirtioNet, ram: GuestRAM) {
        self.dev = dev
        self.ram = ram
    }

    private func r32(_ off: UInt64) -> UInt32 { UInt32(truncatingIfNeeded: dev.read(off, size: 4)) }
    private func w32(_ off: UInt64, _ v: UInt32) { dev.write(off, size: 4, value: UInt64(v)) }

    /// Linux の virtio_mmio + virtio_net と同じ手順でカードを準備する
    func start() throws {
        guard r32(0x000) == 0x7472_6976 else { throw DriverError("virtio の目印がありません") }
        guard r32(0x008) == 1 else { throw DriverError("ネットワークのカードではありません") }
        w32(0x070, 0)                     // リセット
        w32(0x070, 1)                     // ACKNOWLEDGE（見つけた）
        w32(0x070, 1 | 2)                 // DRIVER（使い方が分かる）
        w32(0x014, 0)
        let features = r32(0x010)
        w32(0x024, 0)
        w32(0x020, features & (1 << 5))   // MAC アドレスだけ使う
        w32(0x028, 4096)                  // GuestPageSize
        mac = (0..<6).map { UInt8(truncatingIfNeeded: dev.read(0x100 + UInt64($0), size: 1)) }
        rx = setupQueue(0)
        tx = setupQueue(1)
        // 受け取り用: 空の入れ物を全部並べる
        for i in 0..<qsize {
            writeDesc(rx, i, addr: rx.bufs[i], len: bufSize, writable: true)
            ram.store16(rx.avail + 4 + 2 * UInt64(i), UInt16(i))
        }
        rx.availIdx = UInt16(qsize)
        ram.store16(rx.avail + 2, rx.availIdx)
        txFree = Array(0..<qsize)
        w32(0x070, 1 | 2 | 4)             // DRIVER_OK（使い始める）
        w32(0x050, 0)                     // 受け取り用のキューを通知
    }

    struct DriverError: Error, CustomStringConvertible { let description: String; init(_ s: String) { description = s } }

    /// キューを 1 つ用意する（古い形: ページ番号 = PFN で場所を伝える）
    private func setupQueue(_ q: UInt32) -> Ring {
        w32(0x030, q)                     // QueueSel
        let maxN = Int(r32(0x034))
        precondition(maxN >= qsize)
        w32(0x038, UInt32(qsize))         // QueueNum
        w32(0x03C, 4096)                  // QueueAlign
        // 記述子表 (16 × n) + avail (4 + 2n + 2)、used は 4096 の倍数から (4 + 8n + 2)
        let n = UInt64(qsize)
        let availEnd = 16 * n + 4 + 2 * n + 2
        let usedOff = (availEnd + 4095) / 4096 * 4096
        let total = Int(usedOff + 4 + 8 * n + 2)
        let area = ram.alloc(total, align: 4096)
        var r = Ring()
        r.desc = area
        r.avail = area + 16 * n
        r.used = area + usedOff
        r.bufs = (0..<qsize).map { _ in ram.alloc(bufSize, align: 64) }
        w32(0x040, UInt32((area) / 4096))   // QueuePFN
        return r
    }

    private func writeDesc(_ r: Ring, _ i: Int, addr: UInt64, len: Int, writable: Bool) {
        let d = r.desc + 16 * UInt64(i)
        ram.store64(d, addr)
        ram.store32(d + 8, UInt32(len))
        ram.store16(d + 12, writable ? 2 : 0)
        ram.store16(d + 14, 0)
    }

    /// フレームを送る（入れ物が無ければ、空くまで待たせる）
    func send(_ frame: [UInt8]) {
        txWaiting.append(frame)
        reclaimTX()
        flushTX()
    }

    private func flushTX() {
        var did = false
        while !txWaiting.isEmpty, let i = txFree.popLast() {
            let frame = txWaiting.removeFirst()
            let p = ram.pointer(tx.bufs[i])
            p.initializeMemory(as: UInt8.self, repeating: 0, count: VirtioNet.headerSize)
            let n = min(frame.count, bufSize - VirtioNet.headerSize)
            frame.withUnsafeBytes { (p + VirtioNet.headerSize).copyMemory(from: $0.baseAddress!, byteCount: n) }
            writeDesc(tx, i, addr: tx.bufs[i], len: VirtioNet.headerSize + n, writable: false)
            ram.store16(tx.avail + 4 + 2 * UInt64(Int(tx.availIdx) % qsize), UInt16(i))
            tx.availIdx &+= 1
            ram.store16(tx.avail + 2, tx.availIdx)
            sent += 1
            did = true
        }
        if did { w32(0x050, 1) }          // 送り出し用のキューを通知 → カードが onTransmit に渡す
    }

    /// 送り終わった入れ物を回収する
    private func reclaimTX() {
        let usedIdx = ram.load16(tx.used + 2)
        while tx.lastUsed != usedIdx {
            let id = Int(ram.load32(tx.used + 4 + 8 * UInt64(Int(tx.lastUsed) % qsize)))
            if id < qsize { txFree.append(id) }
            tx.lastUsed &+= 1
        }
    }

    /// 割り込みが来ていれば、届いたフレームを取り出す（カードから知らせがあったときに呼ぶ）
    func poll() {
        guard dev.interruptLine else { return }
        let isr = r32(0x060)
        w32(0x064, isr)                   // 割り込みを受け取った
        reclaimTX()
        flushTX()
        let usedIdx = ram.load16(rx.used + 2)
        var reposted = false
        while rx.lastUsed != usedIdx {
            let slot = rx.used + 4 + 8 * UInt64(Int(rx.lastUsed) % qsize)
            let id = Int(ram.load32(slot))
            let len = Int(ram.load32(slot + 4))
            rx.lastUsed &+= 1
            guard id < qsize else { continue }
            if len > VirtioNet.headerSize {
                let p = ram.pointer(rx.bufs[id]) + VirtioNet.headerSize
                let frame = [UInt8](UnsafeRawBufferPointer(start: p, count: min(len, bufSize) - VirtioNet.headerSize))
                received += 1
                onReceive?(frame)
            }
            // 入れ物を戻す
            ram.store16(rx.avail + 4 + 2 * UInt64(Int(rx.availIdx) % qsize), UInt16(id))
            rx.availIdx &+= 1
            reposted = true
        }
        if reposted {
            ram.store16(rx.avail + 2, rx.availIdx)
            w32(0x050, 0)
        }
    }
}
