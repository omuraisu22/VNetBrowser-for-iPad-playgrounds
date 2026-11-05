#if canImport(Network)
import Foundation
import Network
import Security

// MARK: - UserNet の外への接続を、iPad の Network.framework で作る

final class NWUserNetFactory: UserNetSocketFactory, @unchecked Sendable {
    /// 調査用: 接続の様子をログに出す
    var log: (@Sendable (String) -> Void)?

    func tcp(host: String, port: UInt16, queue: DispatchQueue,
             onReady: @escaping @Sendable () -> Void, onData: @escaping @Sendable (Data) -> Void,
             onClose: @escaping @Sendable (Bool) -> Void) -> UserNetSocket {
        let opts = NWProtocolTCP.Options()
        opts.noDelay = true
        opts.connectionTimeout = 15
        let params = NWParameters(tls: nil, tcp: opts)
        // iPad の「プロキシ」（iCloud プライベートリレーなど）を通さず、相手に直接つなぐ。
        // プロキシを通ると、暗号化していない http の要求がプロキシに読まれて「400 Bad Request」で断られることがある
        params.preferNoProxies = true
        let c = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port) ?? 80, using: params)
        let s = NWUserNetSocket(c, queue: queue, datagram: false, onData: onData, onClose: onClose)
        let log = self.log
        let name = "\(host):\(port)"
        c.stateUpdateHandler = { [weak s, weak c] st in
            guard let s else { return }
            switch st {
            case .ready:
                // 調査用: プロキシを通っているか
                let proxied = c?.currentPath?.usesInterfaceType(.other) ?? false
                if proxied { log?("[ネット] TCP つながった \(name)（プロキシ経由かも）") }
                if !s.readyCalled { s.readyCalled = true; onReady() }
            case .failed(let e):
                log?("[ネット] TCP 失敗 \(name): \(e)")
                s.closed(error: true)
            case .cancelled: s.closed(error: true)
            case .waiting(let e):
                // 待ち（つながらない・ネットが無いなど）。iPad が自分でやり直すので、ここでは切らない
                // （connectionTimeout を過ぎると failed になる）
                _ = e
            default: break
            }
        }
        c.start(queue: queue)
        return s
    }

    func udp(host: String, port: UInt16, queue: DispatchQueue,
             onData: @escaping @Sendable (Data) -> Void, onClose: @escaping @Sendable () -> Void) -> UserNetSocket {
        let params = NWParameters.udp
        params.preferNoProxies = true
        let c = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port) ?? 53, using: params)
        let s = NWUserNetSocket(c, queue: queue, datagram: true, onData: onData, onClose: { _ in onClose() })
        c.stateUpdateHandler = { [weak s] st in
            switch st {
            case .failed, .cancelled: s?.closed(error: true)
            default: break
            }
        }
        c.start(queue: queue)
        return s
    }
}

final class NWUserNetSocket: UserNetSocket, @unchecked Sendable {
    let conn: NWConnection
    let queue: DispatchQueue
    let datagram: Bool
    let onData: @Sendable (Data) -> Void
    let onClose: @Sendable (Bool) -> Void
    var readyCalled = false
    private var done = false

    init(_ c: NWConnection, queue: DispatchQueue, datagram: Bool, onData: @escaping @Sendable (Data) -> Void, onClose: @escaping @Sendable (Bool) -> Void) {
        conn = c; self.queue = queue; self.datagram = datagram; self.onData = onData; self.onClose = onClose
    }

    func closed(error: Bool) {
        if done { return }
        done = true
        conn.cancel()
        onClose(error)
    }

    func send(_ data: Data) {
        if done { return }
        conn.send(content: data, completion: .contentProcessed { _ in })
    }

    func finish() {
        if done || datagram { return }
        conn.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { _ in })
    }

    func close() {
        if done { return }
        done = true
        conn.cancel()
    }

    func readMore() {
        if done { return }
        if datagram {
            conn.receiveMessage { [weak self] data, _, _, error in
                guard let self, !self.done else { return }
                if let d = data, !d.isEmpty { self.onData(d) }
                if error != nil { self.closed(error: true); return }
                self.readMore()          // UDP は続けて受け取る
            }
            return
        }
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self, !self.done else { return }
            if let d = data, !d.isEmpty {
                self.onData(d)
                if isComplete { self.closed(error: false) }
                return
            }
            if isComplete || error != nil { self.closed(error: error != nil) }
            else { self.readMore() }
        }
    }
}
#endif

#if canImport(Network)
// MARK: - ページ（JavaScript）と UserNet の間でフレームを受け渡す
//
// ・POST net/tx: [長さ 2 バイト][フレーム]... をまとめて受け取り、UserNet に渡す
// ・GET net/rx: ゲストへ送るフレームがあれば、まとめて返す。無ければ来るまで（最大 0.5 秒）待たせる
final class NetBridge: @unchecked Sendable {
    let factory = NWUserNetFactory()
    let net: UserNet
    private let lock = NSLock()
    private var out = Data()
    private var waiters: [Waiter] = []
    private(set) var txFrames = 0
    private(set) var rxFrames = 0

    final class Waiter: @unchecked Sendable {
        private let reply: @Sendable (Data) -> Void
        private let lock = NSLock()
        private var done = false
        init(_ r: @escaping @Sendable (Data) -> Void) { reply = r }
        func finish(_ d: Data) {
            lock.lock()
            if done { lock.unlock(); return }
            done = true
            lock.unlock()
            reply(d)
        }
    }

    /// log: 調査用のログ（どのスレッドからも呼ばれる）
    init(log: (@Sendable (String) -> Void)? = nil) {
        net = UserNet(factory: factory)
        factory.log = log
        net.log = log
        net.debug = false            // true にすると、接続ごとの細かいログが出る（調べるとき用）
        // 調べるとき用: NetBridge.selfTest(log:) で、iPad から直接 http / https を読んでみられる
        net.hostLoopback = nil          // 10.0.2.2 から iPad の中（アプリのサーバなど）へはつながせない
        net.onFrame = { [weak self] f in self?.push(f) }
    }

    private func push(_ f: [UInt8]) {
        lock.lock()
        if out.count < (4 << 20) {
            out.append(UInt8(f.count & 0xFF))
            out.append(UInt8(f.count >> 8))
            out.append(contentsOf: f)
            rxFrames += 1
        }
        let ws = waiters
        waiters = []
        var data = Data()
        if !ws.isEmpty { data = out; out = Data() }
        lock.unlock()
        for (i, w) in ws.enumerated() { w.finish(i == 0 ? data : Data()) }
    }

    func transmit(_ body: Data) {
        let b = [UInt8](body)
        var o = 0
        var n = 0
        while o + 2 <= b.count {
            let len = Int(b[o]) | Int(b[o + 1]) << 8
            guard o + 2 + len <= b.count else { break }
            net.input(Array(b[(o + 2)..<(o + 2 + len)]))
            o += 2 + len
            n += 1
        }
        lock.lock(); txFrames += n; lock.unlock()
    }

    func poll(_ reply: @escaping @Sendable (Data) -> Void) {
        lock.lock()
        if !out.isEmpty {
            let d = out
            out = Data()
            lock.unlock()
            reply(d)
            return
        }
        let w = Waiter(reply)
        waiters.append(w)
        lock.unlock()
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.5) { [weak self] in
            if let self { self.lock.lock(); self.waiters.removeAll { $0 === w }; self.lock.unlock() }
            w.finish(Data())
        }
    }

    /// 調査用: iPad から直接 example.com の http を読んでみる（名前でつなぐ・IP でつなぐ、の 2 通り）。
    /// Android を通さずに同じ 400 が返るなら、iPad かネットワークの側（フィルター・VPN など）が返事をしている
    static func selfTest(log: @escaping @Sendable (String) -> Void) {
        let q = DispatchQueue(label: "net-selftest")
        @Sendable func probe(_ host: String, _ label: String) {
            let params = NWParameters.tcp
            params.preferNoProxies = true
            let c = NWConnection(host: NWEndpoint.Host(host), port: 80, using: params)
            c.stateUpdateHandler = { [weak c] st in
                switch st {
                case .ready:
                    guard let conn = c else { return }
                    let req = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\nConnection: close\r\n\r\n"
                    conn.send(content: Data(req.utf8), completion: .contentProcessed { _ in })
                    conn.receive(minimumIncompleteLength: 1, maximumLength: 4096) { d, _, _, e in
                        log("[ネット試験] \(label): " + (d.map { UserNet.preview($0) } ?? "返事なし \(String(describing: e))"))
                        conn.cancel()
                    }
                case .failed(let e): log("[ネット試験] \(label): 失敗 \(e)"); c?.cancel()
                case .waiting(let e): log("[ネット試験] \(label): 待ち \(e)")
                default: break
                }
            }
            c.start(queue: q)
        }
        probe("example.com", "名前で")
        // https（443）: 証明書を誰が出しているかを見る（途中で横取りされていれば、知らない名前が出る）
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, trust, complete in
            let t = sec_trust_copy_ref(trust).takeRetainedValue()
            var names: [String] = []
            if let chain = SecTrustCopyCertificateChain(t) as? [SecCertificate] {
                for c in chain { names.append((SecCertificateCopySubjectSummary(c) as String?) ?? "?") }
            }
            var err: CFError?
            let ok = SecTrustEvaluateWithError(t, &err)
            log("[ネット試験] https の証明書: " + names.joined(separator: " ← ") + "（iPad の判定: \(ok ? "信頼できる" : "信頼できない")）")
            complete(true)
        }, q)
        let tc = NWConnection(host: "example.com", port: 443, using: NWParameters(tls: tls, tcp: .init()))
        tc.stateUpdateHandler = { [weak tc] st in
            switch st {
            case .ready:
                guard let conn = tc else { return }
                let req = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\nConnection: close\r\n\r\n"
                conn.send(content: Data(req.utf8), completion: .contentProcessed { _ in })
                conn.receive(minimumIncompleteLength: 1, maximumLength: 4096) { d, _, _, e in
                    log("[ネット試験] https: " + (d.map { UserNet.preview($0) } ?? "返事なし \(String(describing: e))"))
                    conn.cancel()
                }
            case .failed(let e): log("[ネット試験] https: 失敗 \(e)"); tc?.cancel()
            default: break
            }
        }
        tc.start(queue: q)
        q.async {
            if let ip = UserNet.resolveIPv4("example.com")?.first {
                probe(UserNet.ipString(ip), "IP(\(UserNet.ipString(ip)))で")
            }
        }
    }

    func counts() -> (Int, Int) {
        lock.lock(); defer { lock.unlock() }
        return (txFrames, rxFrames)
    }

    func stop() {
        net.shutdown()
        lock.lock()
        let ws = waiters
        waiters = []
        lock.unlock()
        for w in ws { w.finish(Data()) }
    }
}
#endif
