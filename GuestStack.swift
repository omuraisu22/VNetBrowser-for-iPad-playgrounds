import Foundation

// MARK: - ゲスト側の小さな TCP/IP（Linux の代わり）
//
// ・DHCP で IP アドレスをもらう（ルーター UserNet が 10.0.2.15 をくれる）
// ・ARP でルーター（10.0.2.2）の MAC アドレスを調べる
// ・DNS（10.0.2.3）で名前を IP アドレスにする
// ・TCP でつなぐ（送り直し・順番の確認など最低限）
// すべて queue（VNetMachine.queue）の上で動く

final class GuestStack: @unchecked Sendable {
    let queue: DispatchQueue
    /// フレームを送る（ドライバへ）
    var output: (([UInt8]) -> Void)?
    /// 何が起きたかを知らせる（画面のログ用）
    var trace: ((String) -> Void)?

    var mac: [UInt8] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56]
    private(set) var ip: [UInt8] = [0, 0, 0, 0]
    private(set) var router: [UInt8] = [10, 0, 2, 2]
    private(set) var dns: [UInt8] = [10, 0, 2, 3]
    private(set) var ready = false
    private var routerMAC: [UInt8]?
    private var waitingForARP: [[UInt8]] = []       // ルーターの MAC が分かるまで待たせる IP パケット
    private var ipID: UInt16 = 1
    private var dhcpXID = UInt32.random(in: 1...UInt32.max)
    private var onReady: [() -> Void] = []
    private var timer: DispatchSourceTimer?

    init(queue: DispatchQueue) {
        self.queue = queue
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + .milliseconds(250), repeating: .milliseconds(250))
        t.setEventHandler { [weak self] in self?.tick() }
        t.resume()
        timer = t
    }

    deinit { timer?.cancel() }

    // MARK: 受け取り

    func input(_ f: [UInt8]) {
        guard f.count >= 14 else { return }
        let type = UInt16(f[12]) << 8 | UInt16(f[13])
        let body = Array(f[14...])
        if type == 0x0806 { handleARP(body) } else if type == 0x0800 { handleIPv4(body) }
    }

    // MARK: イーサネット・ARP

    private func sendEthernet(_ type: UInt16, to dst: [UInt8], _ payload: [UInt8]) {
        output?(dst + mac + [UInt8(type >> 8), UInt8(type & 0xFF)] + payload)
    }

    private func askRouterMAC() {
        var a: [UInt8] = [0, 1, 8, 0, 6, 4, 0, 1]
        a += mac + ip + [0, 0, 0, 0, 0, 0] + router
        sendEthernet(0x0806, to: [255, 255, 255, 255, 255, 255], a)
        trace?("→ ARP 10.0.2.2 はどこ？")
    }

    private func handleARP(_ p: [UInt8]) {
        guard p.count >= 28 else { return }
        let op = p[7]
        let senderMAC = Array(p[8..<14]), senderIP = Array(p[14..<18]), target = Array(p[24..<28])
        if op == 2 && senderIP == router {
            if routerMAC == nil { trace?("← ARP 10.0.2.2 は \(senderMAC.map { String(format: "%02x", $0) }.joined(separator: ":"))") }
            routerMAC = senderMAC
            let w = waitingForARP
            waitingForARP = []
            for pkt in w { sendEthernet(0x0800, to: senderMAC, pkt) }
        } else if op == 1 && target == ip && ip != [0, 0, 0, 0] {
            var r: [UInt8] = [0, 1, 8, 0, 6, 4, 0, 2]
            r += mac + ip + senderMAC + senderIP
            sendEthernet(0x0806, to: senderMAC, r)
        }
    }

    // MARK: IPv4

    static func checksum(_ b: [UInt8], initial: UInt32 = 0) -> UInt16 {
        var s = initial
        var i = 0
        while i + 1 < b.count { s &+= UInt32(b[i]) << 8 | UInt32(b[i + 1]); i += 2 }
        if i < b.count { s &+= UInt32(b[i]) << 8 }
        while s >> 16 != 0 { s = (s & 0xFFFF) &+ (s >> 16) }
        return ~UInt16(s)
    }

    static func l4checksum(proto: UInt8, src: [UInt8], dst: [UInt8], _ seg: [UInt8]) -> UInt16 {
        var s: UInt32 = 0
        s &+= UInt32(src[0]) << 8 | UInt32(src[1]); s &+= UInt32(src[2]) << 8 | UInt32(src[3])
        s &+= UInt32(dst[0]) << 8 | UInt32(dst[1]); s &+= UInt32(dst[2]) << 8 | UInt32(dst[3])
        s &+= UInt32(proto); s &+= UInt32(seg.count)
        return checksum(seg, initial: s)
    }

    private func sendIPv4(proto: UInt8, dst: [UInt8], _ body: [UInt8], broadcast: Bool = false) {
        let total = 20 + body.count
        var h: [UInt8] = [0x45, 0, UInt8(total >> 8), UInt8(total & 0xFF), UInt8(ipID >> 8), UInt8(ipID & 0xFF), 0x40, 0, 64, proto, 0, 0]
        ipID &+= 1
        h += ip + dst
        let c = GuestStack.checksum(h)
        h[10] = UInt8(c >> 8); h[11] = UInt8(c & 0xFF)
        let pkt = h + body
        if broadcast { sendEthernet(0x0800, to: [255, 255, 255, 255, 255, 255], pkt); return }
        // 外へは全部ルーター経由（10.0.2.x もルーターが答える）
        if let m = routerMAC { sendEthernet(0x0800, to: m, pkt) } else {
            waitingForARP.append(pkt)
            askRouterMAC()
        }
    }

    private func handleIPv4(_ p: [UInt8]) {
        guard p.count >= 20, p[0] >> 4 == 4 else { return }
        let ihl = Int(p[0] & 15) * 4
        let total = min(Int(p[2]) << 8 | Int(p[3]), p.count)
        guard ihl >= 20, total >= ihl else { return }
        let src = Array(p[12..<16])
        let body = Array(p[ihl..<total])
        switch p[9] {
        case 6: handleTCP(src: src, body)
        case 17: handleUDP(src: src, body)
        default: break
        }
    }

    // MARK: UDP（DHCP と DNS）

    private func sendUDP(sport: UInt16, dst: [UInt8], dport: UInt16, _ payload: [UInt8], broadcast: Bool = false) {
        let len = 8 + payload.count
        var u: [UInt8] = [UInt8(sport >> 8), UInt8(sport & 0xFF), UInt8(dport >> 8), UInt8(dport & 0xFF), UInt8(len >> 8), UInt8(len & 0xFF), 0, 0]
        u += payload
        var c = GuestStack.l4checksum(proto: 17, src: ip, dst: dst, u)
        if c == 0 { c = 0xFFFF }
        u[6] = UInt8(c >> 8); u[7] = UInt8(c & 0xFF)
        sendIPv4(proto: 17, dst: dst, u, broadcast: broadcast)
    }

    private func handleUDP(src: [UInt8], _ b: [UInt8]) {
        guard b.count >= 8 else { return }
        let sport = UInt16(b[0]) << 8 | UInt16(b[1]), dport = UInt16(b[2]) << 8 | UInt16(b[3])
        let len = min(Int(b[4]) << 8 | Int(b[5]), b.count)
        guard len >= 8 else { return }
        let payload = Array(b[8..<len])
        if sport == 67 && dport == 68 { handleDHCP(payload) }
        else if sport == 53, let q = dnsQueries[dport] { dnsQueries[dport] = nil; q.finish(payload) }
    }

    // MARK: DHCP

    /// IP アドレスをもらう（もらえたら done が呼ばれる）
    func start(_ done: @escaping () -> Void) {
        onReady.append(done)
        sendDHCP(type: 1, requested: nil)
    }

    private var dhcpSentAt = Date.distantPast

    private func sendDHCP(type: UInt8, requested: [UInt8]?) {
        var m = [UInt8](repeating: 0, count: 240)
        m[0] = 1; m[1] = 1; m[2] = 6
        m[4] = UInt8(dhcpXID >> 24); m[5] = UInt8((dhcpXID >> 16) & 0xFF); m[6] = UInt8((dhcpXID >> 8) & 0xFF); m[7] = UInt8(dhcpXID & 0xFF)
        m[10] = 0x80                                       // ブロードキャストで返してほしい
        for k in 0..<6 { m[28 + k] = mac[k] }
        m[236] = 99; m[237] = 130; m[238] = 83; m[239] = 99
        m += [53, 1, type]
        if let r = requested { m += [50, 4] + r + [54, 4] + router }
        m += [55, 3, 1, 3, 6, 255]
        sendUDP(sport: 68, dst: [255, 255, 255, 255], dport: 67, m, broadcast: true)
        dhcpSentAt = Date()
        trace?(type == 1 ? "→ DHCP DISCOVER（IP アドレスをください）" : "→ DHCP REQUEST")
    }

    private func handleDHCP(_ p: [UInt8]) {
        guard p.count >= 240, p[0] == 2 else { return }
        let xid = UInt32(p[4]) << 24 | UInt32(p[5]) << 16 | UInt32(p[6]) << 8 | UInt32(p[7])
        guard xid == dhcpXID else { return }
        let yiaddr = Array(p[16..<20])
        var type: UInt8 = 0
        var i = 240
        while i + 1 < p.count {
            let code = p[i]
            if code == 255 { break }
            if code == 0 { i += 1; continue }
            let l = Int(p[i + 1])
            guard i + 2 + l <= p.count else { break }
            let v = Array(p[(i + 2)..<(i + 2 + l)])
            switch code {
            case 53: type = v.first ?? 0
            case 3: if v.count >= 4 { router = Array(v[0..<4]) }
            case 6: if v.count >= 4 { dns = Array(v[0..<4]) }
            default: break
            }
            i += 2 + l
        }
        if type == 2 {
            trace?("← DHCP OFFER \(UserNet.ipString(yiaddr))")
            sendDHCP(type: 3, requested: yiaddr)
        } else if type == 5 && !ready {
            ip = yiaddr
            ready = true
            trace?("← DHCP ACK: IP \(UserNet.ipString(ip))・ルーター \(UserNet.ipString(router))・DNS \(UserNet.ipString(dns))")
            let w = onReady
            onReady = []
            for f in w { f() }
        }
    }

    // MARK: DNS

    private final class DNSQuery: @unchecked Sendable {
        let name: String
        let done: ([UInt8]?) -> Void
        let packet: [UInt8]
        var sentAt = Date()
        var tries = 0
        var finished = false
        init(name: String, packet: [UInt8], done: @escaping ([UInt8]?) -> Void) { self.name = name; self.packet = packet; self.done = done }
        func finish(_ reply: [UInt8]?) {
            if finished { return }
            finished = true
            done(reply.flatMap { DNSQuery.firstA($0) })
        }
        /// 返事から最初の A レコード（IPv4 アドレス）を取り出す
        static func firstA(_ r: [UInt8]) -> [UInt8]? {
            guard r.count >= 12, r[3] & 0x0F == 0 else { return nil }
            let qd = Int(r[4]) << 8 | Int(r[5]), an = Int(r[6]) << 8 | Int(r[7])
            var i = 12
            func skipName() {
                while i < r.count {
                    let l = Int(r[i])
                    if l == 0 { i += 1; return }
                    if l & 0xC0 == 0xC0 { i += 2; return }
                    i += 1 + l
                }
            }
            for _ in 0..<qd { skipName(); i += 4 }
            for _ in 0..<an {
                skipName()
                guard i + 10 <= r.count else { return nil }
                let type = Int(r[i]) << 8 | Int(r[i + 1])
                let rdlen = Int(r[i + 8]) << 8 | Int(r[i + 9])
                i += 10
                if type == 1 && rdlen == 4 && i + 4 <= r.count { return Array(r[i..<(i + 4)]) }
                i += rdlen
            }
            return nil
        }
    }
    private var dnsQueries: [UInt16: DNSQuery] = [:]
    private var nextPort: UInt16 = 40000

    private func allocPort() -> UInt16 {
        nextPort = nextPort >= 60000 ? 40000 : nextPort + 1
        return nextPort
    }

    /// 名前を IPv4 アドレスにする（IP アドレスの形ならそのまま）
    func resolve(_ name: String, _ done: @escaping ([UInt8]?) -> Void) {
        let parts = name.split(separator: ".").compactMap { UInt8($0) }
        if parts.count == 4 && name.split(separator: ".").count == 4 { done(parts); return }
        var q: [UInt8] = [UInt8.random(in: 0...255), UInt8.random(in: 0...255), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]
        for label in name.split(separator: ".") {
            let b = Array(label.utf8)
            q += [UInt8(min(b.count, 63))] + b.prefix(63)
        }
        q += [0, 0, 1, 0, 1]
        let port = allocPort()
        let query = DNSQuery(name: name, packet: q) { [weak self] ip in
            self?.trace?("← DNS \(name) = " + (ip.map { UserNet.ipString($0) } ?? "見つからない"))
            done(ip)
        }
        dnsQueries[port] = query
        trace?("→ DNS \(name) は？")
        sendUDP(sport: port, dst: dns, dport: 53, q)
    }

    // MARK: TCP

    private struct TCPKey: Hashable { let lport: UInt16; let rip: [UInt8]; let rport: UInt16 }
    private var tcps: [TCPKey: GuestTCP] = [:]

    /// TCP でつなぐ
    func connect(_ rip: [UInt8], _ rport: UInt16, handler: GuestTCP.Handler) -> GuestTCP {
        let c = GuestTCP(stack: self, lport: allocPort(), rip: rip, rport: rport, handler: handler)
        tcps[TCPKey(lport: c.lport, rip: rip, rport: rport)] = c
        c.sendSegment(flags: GuestTCP.SYN, payload: [], mss: true)
        trace?("→ TCP SYN \(UserNet.ipString(rip)):\(rport)")
        return c
    }

    fileprivate func forget(_ c: GuestTCP) {
        tcps[TCPKey(lport: c.lport, rip: c.rip, rport: c.rport)] = nil
    }

    fileprivate func emitTCP(_ c: GuestTCP, _ seg: [UInt8]) {
        var t = seg
        let cs = GuestStack.l4checksum(proto: 6, src: ip, dst: c.rip, t)
        t[16] = UInt8(cs >> 8); t[17] = UInt8(cs & 0xFF)
        sendIPv4(proto: 6, dst: c.rip, t)
    }

    private func handleTCP(src: [UInt8], _ b: [UInt8]) {
        guard b.count >= 20 else { return }
        let sport = UInt16(b[0]) << 8 | UInt16(b[1]), dport = UInt16(b[2]) << 8 | UInt16(b[3])
        guard let c = tcps[TCPKey(lport: dport, rip: src, rport: sport)] else { return }
        c.input(b)
    }

    private func tick() {
        if !ready && Date().timeIntervalSince(dhcpSentAt) > 2 && !onReady.isEmpty { sendDHCP(type: 1, requested: nil) }
        let now = Date()
        for (port, q) in dnsQueries where now.timeIntervalSince(q.sentAt) > 2 {
            q.tries += 1
            if q.tries > 3 { dnsQueries[port] = nil; q.finish(nil); continue }
            q.sentAt = now
            sendUDP(sport: port, dst: dns, dport: 53, q.packet)
        }
        for c in Array(tcps.values) { c.tick(now) }
    }
}

// MARK: - ゲスト側の TCP の接続 1 本

final class GuestTCP: @unchecked Sendable {
    struct Handler {
        var connected: () -> Void
        var data: (Data) -> Void
        var closed: (_ error: String?) -> Void
    }
    static let FIN: UInt8 = 1, SYN: UInt8 = 2, RST: UInt8 = 4, PSH: UInt8 = 8, ACK: UInt8 = 16

    unowned let stack: GuestStack
    let lport: UInt16, rip: [UInt8], rport: UInt16
    private let handler: Handler
    private enum State { case synSent, established, closed }
    private var state = State.synSent
    private let iss = UInt32.random(in: 0...UInt32.max)
    private var sndUna: UInt32, sndNxt: UInt32
    private var rcvNxt: UInt32 = 0
    private var sendBuf = Data()        // sndUna から先の、まだ受け取ってもらっていないデータ
    private var wantFIN = false, finSent = false, gotFIN = false
    private var peerWindow = 65535
    private var mss = 1460
    private var lastProgress = Date()
    private var retries = 0
    private(set) var bytesIn = 0, bytesOut = 0

    fileprivate init(stack: GuestStack, lport: UInt16, rip: [UInt8], rport: UInt16, handler: Handler) {
        self.stack = stack; self.lport = lport; self.rip = rip; self.rport = rport; self.handler = handler
        sndUna = iss
        sndNxt = iss &+ 1
    }

    fileprivate func sendSegment(flags: UInt8, payload: ArraySlice<UInt8>, seq: UInt32? = nil, mss withMSS: Bool = false) {
        let s = seq ?? (flags & GuestTCP.SYN != 0 ? iss : sndNxt)
        let hlen = withMSS ? 24 : 20
        var t: [UInt8] = [UInt8(lport >> 8), UInt8(lport & 0xFF), UInt8(rport >> 8), UInt8(rport & 0xFF)]
        t += [UInt8(s >> 24), UInt8((s >> 16) & 0xFF), UInt8((s >> 8) & 0xFF), UInt8(s & 0xFF)]
        let a = flags & GuestTCP.ACK != 0 ? rcvNxt : 0
        t += [UInt8(a >> 24), UInt8((a >> 16) & 0xFF), UInt8((a >> 8) & 0xFF), UInt8(a & 0xFF)]
        t += [UInt8(hlen / 4) << 4, flags, 0xFF, 0xFF, 0, 0, 0, 0]
        if withMSS { t += [2, 4, 0x05, 0xB4] }
        t += payload
        stack.emitTCP(self, t)
    }

    /// データを送る
    func write(_ d: Data) {
        guard state != .closed else { return }
        sendBuf.append(d)
        bytesOut += d.count
        pump()
    }

    /// 送り終わったら閉じる
    func close() {
        wantFIN = true
        pump()
    }

    func abort() {
        if state != .closed { sendSegment(flags: GuestTCP.RST | GuestTCP.ACK, payload: []) }
        finish(nil)
    }

    private func finish(_ error: String?) {
        if state == .closed { return }
        state = .closed
        stack.forget(self)
        handler.closed(error)
    }

    private func pump() {
        guard state == .established else { return }
        while true {
            let inFlight = Int(sndNxt &- sndUna)
            let unsent = sendBuf.count - inFlight
            if unsent <= 0 {
                if wantFIN && !finSent {
                    sendSegment(flags: GuestTCP.FIN | GuestTCP.ACK, payload: [])
                    sndNxt &+= 1
                    finSent = true
                    lastProgress = Date()
                }
                return
            }
            let room = peerWindow - inFlight
            if room <= 0 { return }
            let n = min(unsent, mss, room)
            let start = sendBuf.startIndex + inFlight
            sendSegment(flags: GuestTCP.ACK | GuestTCP.PSH, payload: ArraySlice(sendBuf[start..<(start + n)]))
            sndNxt &+= UInt32(n)
            lastProgress = Date()
        }
    }

    fileprivate func input(_ b: [UInt8]) {
        let seq = UInt32(b[4]) << 24 | UInt32(b[5]) << 16 | UInt32(b[6]) << 8 | UInt32(b[7])
        let ack = UInt32(b[8]) << 24 | UInt32(b[9]) << 16 | UInt32(b[10]) << 8 | UInt32(b[11])
        let off = Int(b[12] >> 4) * 4
        let flags = b[13]
        guard off >= 20, off <= b.count else { return }
        let payload = b[off...]
        peerWindow = Int(b[14]) << 8 | Int(b[15])
        if flags & GuestTCP.RST != 0 {
            stack.trace?("← TCP RST \(UserNet.ipString(rip)):\(rport)")
            finish(state == .synSent ? "つながりませんでした" : "相手に切られました")
            return
        }
        if state == .synSent {
            guard flags & GuestTCP.SYN != 0, flags & GuestTCP.ACK != 0, ack == iss &+ 1 else { return }
            rcvNxt = seq &+ 1
            sndUna = ack
            state = .established
            retries = 0
            sendSegment(flags: GuestTCP.ACK, payload: [])
            stack.trace?("← TCP SYN+ACK \(UserNet.ipString(rip)):\(rport)（つながった）")
            handler.connected()
            pump()
            return
        }
        guard state == .established else { return }
        if flags & GuestTCP.ACK != 0 {
            let acked = ack &- sndUna
            let inFlight = sndNxt &- sndUna
            if acked > 0 && acked <= inFlight {
                var n = Int(acked)
                if finSent && ack == sndNxt { n -= 1 }      // FIN の分
                if n > 0 { sendBuf.removeFirst(min(n, sendBuf.count)) }
                sndUna = ack
                lastProgress = Date()
                retries = 0
            }
        }
        var needAck = false
        if !payload.isEmpty {
            if seq == rcvNxt {
                rcvNxt &+= UInt32(payload.count)
                bytesIn += payload.count
                handler.data(Data(payload))
            }
            needAck = true
        }
        if flags & GuestTCP.FIN != 0 && seq &+ UInt32(payload.count) == rcvNxt && !gotFIN {
            gotFIN = true
            rcvNxt &+= 1
            needAck = true
        }
        if needAck { sendSegment(flags: GuestTCP.ACK, payload: []) }
        pump()
        if gotFIN {
            // 相手が閉じた: こちらも閉じて終わり（ブラウザ用なので、半分だけ閉じた状態は使わない）
            if !finSent { wantFIN = true; pump() }
            finish(nil)
        }
    }

    fileprivate func tick(_ now: Date) {
        if now.timeIntervalSince(lastProgress) < 1 { return }
        if state == .synSent {
            retries += 1
            if retries > 8 { finish("つながりませんでした（時間切れ）"); return }
            sendSegment(flags: GuestTCP.SYN, payload: [], mss: true)
            lastProgress = now
        } else if state == .established && sndNxt != sndUna {
            retries += 1
            if retries > 12 { abort(); return }
            // 受け取りの返事が来ない: 先頭から送り直す
            sndNxt = sndUna
            if finSent { finSent = false }
            lastProgress = now
            pump()
        }
    }
}
