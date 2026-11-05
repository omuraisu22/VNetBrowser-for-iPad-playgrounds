import Foundation

// MARK: - 全部をつなぐ
//
//  [ゲスト側]  HTTPFetch → GuestStack → VirtioNetDriver
//                                         ↓ ↑（RAM の中のキューと、レジスタ）
//  [カード]                             VirtioNet（エミュレータと同じ）
//                                         ↓ onTransmit      ↑ receive
//  [ルーター]                           UserNet（小さなルーター）→ iPad の通信 → インターネット
//
// ゲスト側とカードは queue の上で動く。ルーターは自分のキューで動き、フレームを渡すときだけ行き来する

final class VNetMachine: @unchecked Sendable {
    let queue = DispatchQueue(label: "vnet-guest")
    let ram = GuestRAM(megabytes: 2)
    let card: VirtioNet
    let driver: VirtioNetDriver
    let stack: GuestStack
    let router: UserNet
    /// ログ（どのスレッドからも呼ばれる）
    var log: (@Sendable (String) -> Void)?
    private(set) var ready = false
    private var waiting: [() -> Void] = []
    /// 統計: カードを通ったフレームの数とバイト数
    private(set) var framesOut = 0, framesIn = 0, bytesOut = 0, bytesIn = 0

    init(factory: UserNetSocketFactory) {
        card = VirtioNet(base: 0x0A00_0000, irq: 48, memory: ram)
        driver = VirtioNetDriver(dev: card, ram: ram)
        stack = GuestStack(queue: queue)
        router = UserNet(factory: factory)
        router.hostLoopback = nil
        // ゲスト → カード → ルーター
        stack.output = { [unowned self] f in self.driver.send(f) }
        card.onTransmit = { [unowned self] f in
            self.framesOut += 1; self.bytesOut += f.count
            self.router.input(f)
        }
        // ルーター → カード → ゲスト（カードとゲストは queue の上で触る）
        router.onFrame = { [weak self] f in
            guard let self else { return }
            self.queue.async {
                self.framesIn += 1; self.bytesIn += f.count
                self.card.receive(f)
                self.driver.poll()          // 割り込みを見て、届いたフレームを取り出す
            }
        }
        driver.onReceive = { [unowned self] f in self.stack.input(f) }
        stack.trace = { [weak self] s in self?.log?(s) }
        router.log = { [weak self] s in self?.log?(s) }
    }

    /// カードを準備して DHCP で IP アドレスをもらう
    func boot() {
        queue.async {
            do {
                try self.driver.start()
                self.stack.mac = self.driver.mac
                self.log?("カードの準備ができました（MAC \(self.driver.mac.map { String(format: "%02x", $0) }.joined(separator: ":"))）")
            } catch {
                self.log?("カードを準備できません: \(error)")
                return
            }
            self.stack.start {
                self.ready = true
                let w = self.waiting
                self.waiting = []
                for f in w { f() }
            }
        }
    }

    /// URL を読む（結果は done に、queue の上で返る）
    func fetch(_ url: URL, _ done: @escaping @Sendable (Result<HTTPResult, HTTPFetch.FetchError>) -> Void) {
        queue.async {
            let go = {
                // 取得が終わるまで、取得の物を持っておく（終わったら手放す）
                let box = FetchBox()
                let f = HTTPFetch(stack: self.stack, url: url) { r in
                    box.fetch = nil
                    done(r)
                }
                box.fetch = f
                f.start()
            }
            if self.ready { go() } else { self.waiting.append(go) }
        }
    }

    private final class FetchBox: @unchecked Sendable { var fetch: HTTPFetch? }

    func stats() -> String {
        "フレーム 送 \(framesOut)（\(bytesOut / 1024)KB）・受 \(framesIn)（\(bytesIn / 1024)KB）"
    }
}
