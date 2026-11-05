import Foundation

// MARK: - アプリの中の小さなルーター（ユーザーモードの NAT。QEMU の「SLIRP」と同じ考え方）
//
// Android（ゲスト）の eth0 から出たイーサネットのフレームを受け取り、中身の TCP / UDP を
// iPad の普通の通信（Network.framework）に置き換えて外に出す。返事はフレームに組み立て直してゲストに返す。
//
//   ゲスト 10.0.2.15 ── ルーター 10.0.2.2（＝このクラス）── iPad の通信 ── インターネット
//                        DNS は 10.0.2.3（iPad の名前解決を使う）
//
// ・ARP: 10.0.2.x を聞かれたら、自分の MAC で答える
// ・DHCP: 10.0.2.15 を配る（ルーター 10.0.2.2、DNS 10.0.2.3）
// ・DNS: A レコードは iPad で名前解決して答える。AAAA などは「無し」と答える（IPv4 だけ使う）
// ・TCP: ゲストとの TCP はここで終わらせ、外へは iPad の TCP 接続でつなぐ（中身だけ中継する）
// ・UDP: 宛先ごとに iPad の UDP 接続を作って中継する
// ・ping（ICMP）: 10.0.2.x にだけ答える（iPad のアプリは外へ ping を打てない）
// すべて queue（1 本の直列キュー）の上で動く。

/// 外への接続（TCP か UDP）。受け取りは readMore() を呼ぶたびに 1 回分ずつ届く
protocol UserNetSocket: AnyObject, Sendable {
    func send(_ data: Data)
    /// 送り終わったら閉じる（TCP の FIN）
    func finish()
    func close()
    func readMore()
}

/// 外への接続を作るもの（iPad では Network.framework。試験では普通のソケット）。
/// 呼び出し（onReady など）は必ず queue の上で行うこと
protocol UserNetSocketFactory {
    func tcp(host: String, port: UInt16, queue: DispatchQueue,
             onReady: @escaping @Sendable () -> Void, onData: @escaping @Sendable (Data) -> Void,
             onClose: @escaping @Sendable (_ error: Bool) -> Void) -> UserNetSocket
    func udp(host: String, port: UInt16, queue: DispatchQueue,
             onData: @escaping @Sendable (Data) -> Void, onClose: @escaping @Sendable () -> Void) -> UserNetSocket
}

final class UserNet: @unchecked Sendable {
    let queue = DispatchQueue(label: "usernet")
    let factory: UserNetSocketFactory
    /// ゲストへ送るフレーム（queue の上で呼ばれる）
    var onFrame: (([UInt8]) -> Void)?
    /// 10.0.2.2 宛ての接続をどこへつなぐか（試験用。nil ならつながない）
    var hostLoopback: String? = "127.0.0.1"
    /// 調査用のログ
    var log: ((String) -> Void)?
    var debug = false

    static let myMAC: [UInt8] = [0x52, 0x55, 0x0A, 0x00, 0x02, 0x02]
    static let gateway: [UInt8] = [10, 0, 2, 2]
    static let dnsIP: [UInt8] = [10, 0, 2, 3]
    static let guestIP: [UInt8] = [10, 0, 2, 15]
    var guestMAC: [UInt8] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56]

    private var ipID: UInt16 = 1
    private var tcps: [TCPKey: TCPConn] = [:]
    private var udps: [UDPKey: UDPFlow] = [:]
    private var timer: DispatchSourceTimer?
    /// 統計
    private(set) var stats = (framesIn: 0, framesOut: 0, tcpOpened: 0, udpOpened: 0, dns: 0)

    init(factory: UserNetSocketFactory) {
        self.factory = factory
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + .milliseconds(200), repeating: .milliseconds(200))
        t.setEventHandler { [weak self] in self?.tick() }
        t.resume()
        timer = t
    }

    deinit { timer?.cancel() }

    /// すべての接続を閉じる
    func shutdown() {
        queue.async {
            for c in self.tcps.values { c.sock?.close() }
            for u in self.udps.values { u.sock?.close() }
            self.tcps.removeAll()
            self.udps.removeAll()
            self.timer?.cancel()
        }
    }

    /// ゲストから出たフレーム（どのスレッドからでもよい）
    func input(_ frame: [UInt8]) {
        queue.async { self.handleFrame(frame) }
    }

    // MARK: イーサネット

    private func handleFrame(_ f: [UInt8]) {
        guard f.count >= 14 else { return }
        stats.framesIn += 1
        let type = UInt16(f[12]) << 8 | UInt16(f[13])
        if f[6] & 1 == 0 { guestMAC = Array(f[6..<12]) }
        switch type {
        case 0x0806: handleARP(Array(f[14...]))
        case 0x0800: handleIPv4(Array(f[14...]))
        default: break        // IPv6 などは使わない
        }
    }

    private func sendEthernet(_ type: UInt16, _ payload: [UInt8], to dst: [UInt8]? = nil) {
        var f = dst ?? guestMAC
        f += UserNet.myMAC
        f += [UInt8(type >> 8), UInt8(type & 0xFF)]
        f += payload
        stats.framesOut += 1
        onFrame?(f)
    }

    // MARK: ARP

    private func handleARP(_ p: [UInt8]) {
        guard p.count >= 28, p[6] == 0, p[7] == 1 else { return }     // 問い合わせだけ
        let target = Array(p[24..<28])
        guard target[0] == 10, target[1] == 0, target[2] == 2, target != UserNet.guestIP else { return }
        var r: [UInt8] = [0, 1, 8, 0, 6, 4, 0, 2]
        r += UserNet.myMAC + target
        r += Array(p[8..<14]) + Array(p[14..<18])
        sendEthernet(0x0806, r, to: Array(p[8..<14]))
    }

    // MARK: IPv4

    private func handleIPv4(_ p: [UInt8]) {
        guard p.count >= 20, p[0] >> 4 == 4 else { return }
        let ihl = Int(p[0] & 15) * 4
        let total = min(Int(p[2]) << 8 | Int(p[3]), p.count)
        guard ihl >= 20, total >= ihl else { return }
        let fragment = (UInt16(p[6]) << 8 | UInt16(p[7])) & 0x3FFF
        if fragment != 0 { return }          // 分割されたものは扱わない（MTU 1500 なので普通は来ない）
        let proto = p[9]
        let src = Array(p[12..<16]), dst = Array(p[16..<20])
        let body = Array(p[ihl..<total])
        switch proto {
        case 1: handleICMP(src: src, dst: dst, body)
        case 6: handleTCP(src: src, dst: dst, body)
        case 17: handleUDP(src: src, dst: dst, body)
        default: break
        }
    }

    private func sendIPv4(proto: UInt8, src: [UInt8], dst: [UInt8], _ body: [UInt8]) {
        let total = 20 + body.count
        var h: [UInt8] = [0x45, 0, UInt8(total >> 8), UInt8(total & 0xFF),
                          UInt8(ipID >> 8), UInt8(ipID & 0xFF), 0x40, 0, 64, proto, 0, 0]
        ipID &+= 1
        h += src + dst
        let c = UserNet.checksum(h)
        h[10] = UInt8(c >> 8); h[11] = UInt8(c & 0xFF)
        sendEthernet(0x0800, h + body)
    }

    static func checksum(_ b: [UInt8], initial: UInt32 = 0) -> UInt16 {
        var s = initial
        var i = 0
        let n = b.count
        while i + 1 < n { s &+= UInt32(b[i]) << 8 | UInt32(b[i + 1]); i += 2 }
        if i < n { s &+= UInt32(b[i]) << 8 }
        while s >> 16 != 0 { s = (s & 0xFFFF) &+ (s >> 16) }
        return ~UInt16(s)
    }

    /// TCP / UDP の確認用の値（疑似ヘッダ込み）
    static func l4checksum(proto: UInt8, src: [UInt8], dst: [UInt8], _ seg: [UInt8]) -> UInt16 {
        var s: UInt32 = 0
        s &+= UInt32(src[0]) << 8 | UInt32(src[1]); s &+= UInt32(src[2]) << 8 | UInt32(src[3])
        s &+= UInt32(dst[0]) << 8 | UInt32(dst[1]); s &+= UInt32(dst[2]) << 8 | UInt32(dst[3])
        s &+= UInt32(proto); s &+= UInt32(seg.count)
        return checksum(seg, initial: s)
    }

    /// 調査用: 先頭 100 バイトを読める形にする（文字はそのまま、改行は \r \n、ほかは . ）
    static func preview(_ d: Data) -> String {
        var s = ""
        for b in d.prefix(100) {
            switch b {
            case 0x0D: s += "\\r"
            case 0x0A: s += "\\n"
            case 0x20...0x7E: s.append(Character(Unicode.Scalar(b)))
            default: s += "."
            }
        }
        return s
    }

    static func ipString(_ a: [UInt8]) -> String { a.map { String($0) }.joined(separator: ".") }

    /// ゲストが指定した宛先 IP を、iPad 側でつなぐ相手の名前にする
    private func hostFor(_ ip: [UInt8]) -> String? {
        if ip == UserNet.gateway { return hostLoopback }
        if ip[0] == 10 && ip[1] == 0 && ip[2] == 2 { return nil }
        if ip[0] == 127 || ip[0] == 0 || ip[0] >= 224 { return nil }
        return UserNet.ipString(ip)
    }

    // MARK: ICMP（ping）

    private func handleICMP(src: [UInt8], dst: [UInt8], _ b: [UInt8]) {
        guard b.count >= 8, b[0] == 8, dst[0] == 10, dst[1] == 0, dst[2] == 2 else { return }
        var r = b
        r[0] = 0; r[2] = 0; r[3] = 0
        let c = UserNet.checksum(r)
        r[2] = UInt8(c >> 8); r[3] = UInt8(c & 0xFF)
        sendIPv4(proto: 1, src: dst, dst: src, r)
    }

    // MARK: UDP

    private struct UDPKey: Hashable, Sendable { let sport: UInt16; let dst: [UInt8]; let dport: UInt16 }
    private final class UDPFlow: @unchecked Sendable {
        var sock: UserNetSocket?
        var last = Date()
    }

    private func sendUDP(src: [UInt8], sport: UInt16, dst: [UInt8], dport: UInt16, _ payload: [UInt8]) {
        let len = 8 + payload.count
        var u: [UInt8] = [UInt8(sport >> 8), UInt8(sport & 0xFF), UInt8(dport >> 8), UInt8(dport & 0xFF),
                          UInt8(len >> 8), UInt8(len & 0xFF), 0, 0]
        u += payload
        var c = UserNet.l4checksum(proto: 17, src: src, dst: dst, u)
        if c == 0 { c = 0xFFFF }
        u[6] = UInt8(c >> 8); u[7] = UInt8(c & 0xFF)
        sendIPv4(proto: 17, src: src, dst: dst, u)
    }

    private func handleUDP(src: [UInt8], dst: [UInt8], _ b: [UInt8]) {
        guard b.count >= 8 else { return }
        let sport = UInt16(b[0]) << 8 | UInt16(b[1]), dport = UInt16(b[2]) << 8 | UInt16(b[3])
        let len = min(Int(b[4]) << 8 | Int(b[5]), b.count)
        guard len >= 8 else { return }
        let payload = Array(b[8..<len])
        if dport == 67 { handleDHCP(payload); return }
        if dst == UserNet.dnsIP && dport == 53 { handleDNS(payload, sport: sport); return }
        guard let host = hostFor(dst) else { return }
        let key = UDPKey(sport: sport, dst: dst, dport: dport)
        let flow: UDPFlow
        if let f = udps[key] { flow = f } else {
            stats.udpOpened += 1
            let f = UDPFlow()
            let sock = factory.udp(host: host, port: dport, queue: queue, onData: { [weak self, weak f] d in
                guard let self else { return }
                f?.last = Date()
                self.sendUDP(src: dst, sport: dport, dst: UserNet.guestIP, dport: sport, Array(d))
            }, onClose: { [weak self] in self?.udps[key] = nil })
            f.sock = sock
            flow = f
            udps[key] = f
            sock.readMore()
        }
        flow.last = Date()
        flow.sock?.send(Data(payload))
    }

    // MARK: DHCP

    private func handleDHCP(_ p: [UInt8]) {
        guard p.count >= 240, p[0] == 1, p[236] == 99, p[237] == 130, p[238] == 83, p[239] == 99 else { return }
        var msgType: UInt8 = 0
        var i = 240
        while i < p.count {
            let code = p[i]
            if code == 255 { break }
            if code == 0 { i += 1; continue }
            guard i + 1 < p.count else { break }
            let l = Int(p[i + 1])
            if code == 53, l >= 1, i + 2 < p.count { msgType = p[i + 2] }
            i += 2 + l
        }
        let reply: UInt8
        switch msgType {
        case 1: reply = 2          // DISCOVER → OFFER
        case 3: reply = 5          // REQUEST → ACK
        default: return
        }
        var r = [UInt8](repeating: 0, count: 240)
        r[0] = 2; r[1] = 1; r[2] = 6
        for k in 4..<8 { r[k] = p[k] }                 // xid
        r[10] = p[10]; r[11] = p[11]                   // flags
        for k in 0..<4 { r[16 + k] = UserNet.guestIP[k]; r[20 + k] = UserNet.gateway[k] }
        for k in 0..<16 { r[28 + k] = p[28 + k] }      // chaddr
        r[236] = 99; r[237] = 130; r[238] = 83; r[239] = 99
        r += [53, 1, reply]
        r += [54, 4] + UserNet.gateway
        r += [51, 4, 0, 1, 0x51, 0x80]                 // 86400 秒
        r += [1, 4, 255, 255, 255, 0]
        r += [3, 4] + UserNet.gateway
        r += [6, 4] + UserNet.dnsIP
        r += [26, 2, 0x05, 0xDC]                       // MTU 1500
        r += [255]
        // ブロードキャストで返す（まだ IP を持っていないので）
        let len = 8 + r.count
        var u: [UInt8] = [0, 67, 0, 68, UInt8(len >> 8), UInt8(len & 0xFF), 0, 0]
        u += r
        let bcast: [UInt8] = [255, 255, 255, 255]
        var c = UserNet.l4checksum(proto: 17, src: UserNet.gateway, dst: bcast, u)
        if c == 0 { c = 0xFFFF }
        u[6] = UInt8(c >> 8); u[7] = UInt8(c & 0xFF)
        let total = 20 + u.count
        var h: [UInt8] = [0x45, 0, UInt8(total >> 8), UInt8(total & 0xFF), UInt8(ipID >> 8), UInt8(ipID & 0xFF), 0, 0, 64, 17, 0, 0]
        ipID &+= 1
        h += UserNet.gateway + bcast
        let hc = UserNet.checksum(h)
        h[10] = UInt8(hc >> 8); h[11] = UInt8(hc & 0xFF)
        sendEthernet(0x0800, h + u, to: [255, 255, 255, 255, 255, 255])
        log?("[ネット] DHCP \(reply == 2 ? "OFFER" : "ACK") 10.0.2.15")
    }

    // MARK: DNS

    private func handleDNS(_ q: [UInt8], sport: UInt16) {
        guard q.count >= 12 else { return }
        stats.dns += 1
        let qd = Int(q[4]) << 8 | Int(q[5])
        guard qd == 1 else { sendDNS(q, sport: sport, rcode: 4, answers: [], qEnd: 12); return }
        var i = 12
        var labels: [String] = []
        while i < q.count {
            let l = Int(q[i])
            if l == 0 { i += 1; break }
            guard l < 64, i + 1 + l <= q.count else { return }
            labels.append(String(decoding: q[(i + 1)..<(i + 1 + l)], as: UTF8.self))
            i += 1 + l
        }
        guard i + 4 <= q.count else { return }
        let qtype = Int(q[i]) << 8 | Int(q[i + 1])
        let qEnd = i + 4
        let name = labels.joined(separator: ".")
        if qtype != 1 || name.isEmpty {
            sendDNS(q, sport: sport, rcode: 0, answers: [], qEnd: qEnd)    // A 以外は「無し」
            return
        }
        let queue = self.queue
        DispatchQueue.global(qos: .userInitiated).async {
            let addrs = UserNet.resolveIPv4(name)
            queue.async { [weak self] in
                self?.sendDNS(q, sport: sport, rcode: addrs == nil ? 3 : 0, answers: addrs ?? [], qEnd: qEnd)
            }
        }
    }

    private func sendDNS(_ q: [UInt8], sport: UInt16, rcode: UInt8, answers: [[UInt8]], qEnd: Int) {
        var r = Array(q[0..<min(qEnd, q.count)])
        r[2] = 0x81 | (q[2] & 0x01 != 0 ? 0 : 0)       // QR=1, RD=1
        r[3] = 0x80 | rcode                            // RA=1
        r[6] = UInt8(answers.count >> 8); r[7] = UInt8(answers.count & 0xFF)
        r[8] = 0; r[9] = 0; r[10] = 0; r[11] = 0
        for a in answers {
            r += [0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4] + a
        }
        sendUDP(src: UserNet.dnsIP, sport: 53, dst: UserNet.guestIP, dport: sport, r)
    }

    /// 名前を IPv4 アドレスにする（nil = 見つからない）
    static func resolveIPv4(_ name: String) -> [[UInt8]]? {
        var hints = addrinfo()
        hints.ai_family = AF_INET
        #if canImport(Glibc)
        hints.ai_socktype = Int32(SOCK_STREAM.rawValue)
        #else
        hints.ai_socktype = SOCK_STREAM
        #endif
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(name, nil, &hints, &res) == 0, let first = res else { return nil }
        defer { freeaddrinfo(first) }
        var out: [[UInt8]] = []
        var p: UnsafeMutablePointer<addrinfo>? = first
        while let a = p {
            if a.pointee.ai_family == AF_INET, let sa = a.pointee.ai_addr {
                sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                    let v = sin.pointee.sin_addr.s_addr       // ネットワークの順（ビッグエンディアン）のまま
                    let b = [UInt8(v & 0xFF), UInt8((v >> 8) & 0xFF), UInt8((v >> 16) & 0xFF), UInt8(v >> 24)]
                    if !out.contains(b) { out.append(b) }
                }
            }
            p = a.pointee.ai_next
        }
        return out.isEmpty ? nil : Array(out.prefix(8))
    }

    // MARK: TCP

    private struct TCPKey: Hashable, Sendable { let sport: UInt16; let dst: [UInt8]; let dport: UInt16 }

    private final class TCPConn: @unchecked Sendable {
        let key: TCPKey
        var sock: UserNetSocket?
        var state = State.connecting
        enum State { case connecting, synSent, established, closed }
        var rcvNxt: UInt32 = 0            // ゲストから次に来るはずの番号
        let iss: UInt32                   // こちらの最初の番号
        var sndUna: UInt32 = 0            // ゲストがまだ受け取ったと言っていない最初の番号
        var sndNxt: UInt32 = 0            // 次に送る番号
        var buf = Data()                  // sndUna から先の、外から来た（まだ受け取りの返事が無い）データ
        var window: UInt32 = 65535
        var mss = 536
        var remoteEOF = false             // 外の相手が閉じた
        var finSent = false
        var guestFIN = false
        var lastProgress = Date()
        var retries = 0
        var reading = false
        var lastActivity = Date()
        var totalIn = 0
        var totalOut = 0
        init(key: TCPKey, iss: UInt32) { self.key = key; self.iss = iss }
    }

    static let maxBuffered = 512 * 1024

    private func sendTCP(_ c: TCPConn, flags: UInt8, seq: UInt32, payload: ArraySlice<UInt8> = [], mssOption: Bool = false) {
        let src = c.key.dst, dst = UserNet.guestIP
        let hlen = mssOption ? 24 : 20
        var t: [UInt8] = [UInt8(c.key.dport >> 8), UInt8(c.key.dport & 0xFF), UInt8(c.key.sport >> 8), UInt8(c.key.sport & 0xFF)]
        t += [UInt8(seq >> 24), UInt8((seq >> 16) & 0xFF), UInt8((seq >> 8) & 0xFF), UInt8(seq & 0xFF)]
        let ack = c.rcvNxt
        t += [UInt8(ack >> 24), UInt8((ack >> 16) & 0xFF), UInt8((ack >> 8) & 0xFF), UInt8(ack & 0xFF)]
        // こちらの受け取り窓: 外へ送り切れていない分は気にしない（iPad の接続が受け取る）
        t += [UInt8(hlen / 4) << 4, flags, 0xFF, 0xFF, 0, 0, 0, 0]
        if mssOption { t += [2, 4, 0x05, 0xB4] }      // MSS 1460
        t += payload
        let cs = UserNet.l4checksum(proto: 6, src: src, dst: dst, t)
        t[16] = UInt8(cs >> 8); t[17] = UInt8(cs & 0xFF)
        sendIPv4(proto: 6, src: src, dst: dst, t)
    }

    private func sendRST(src: [UInt8], dst: [UInt8], sport: UInt16, dport: UInt16, seq: UInt32, ack: UInt32) {
        var t: [UInt8] = [UInt8(dport >> 8), UInt8(dport & 0xFF), UInt8(sport >> 8), UInt8(sport & 0xFF)]
        t += [UInt8(seq >> 24), UInt8((seq >> 16) & 0xFF), UInt8((seq >> 8) & 0xFF), UInt8(seq & 0xFF)]
        t += [UInt8(ack >> 24), UInt8((ack >> 16) & 0xFF), UInt8((ack >> 8) & 0xFF), UInt8(ack & 0xFF)]
        t += [0x50, 0x14, 0, 0, 0, 0, 0, 0]            // RST + ACK
        let cs = UserNet.l4checksum(proto: 6, src: dst, dst: src, t)
        t[16] = UInt8(cs >> 8); t[17] = UInt8(cs & 0xFF)
        sendIPv4(proto: 6, src: dst, dst: src, t)
    }

    private func handleTCP(src: [UInt8], dst: [UInt8], _ b: [UInt8]) {
        guard b.count >= 20 else { return }
        let sport = UInt16(b[0]) << 8 | UInt16(b[1]), dport = UInt16(b[2]) << 8 | UInt16(b[3])
        let seq = UInt32(b[4]) << 24 | UInt32(b[5]) << 16 | UInt32(b[6]) << 8 | UInt32(b[7])
        let ack = UInt32(b[8]) << 24 | UInt32(b[9]) << 16 | UInt32(b[10]) << 8 | UInt32(b[11])
        let off = Int(b[12] >> 4) * 4
        let flags = b[13]
        let win = UInt32(b[14]) << 8 | UInt32(b[15])
        guard off >= 20, off <= b.count else { return }
        let payload = b[off...]
        let SYN: UInt8 = 2, RST: UInt8 = 4, ACK: UInt8 = 16, FIN: UInt8 = 1
        let key = TCPKey(sport: sport, dst: dst, dport: dport)

        guard let c = tcps[key] else {
            if flags & RST != 0 { return }
            guard flags & SYN != 0, flags & ACK == 0, let host = hostFor(dst) else {
                // 知らない接続: 終わらせてもらう
                sendRST(src: src, dst: dst, sport: sport, dport: dport, seq: flags & ACK != 0 ? ack : 0,
                        ack: seq &+ UInt32(payload.count) &+ (flags & (SYN | FIN) != 0 ? 1 : 0))
                return
            }
            // 新しい接続: 外へつなぎに行く。つながったら SYN+ACK を返す
            let c = TCPConn(key: key, iss: UInt32.random(in: 0...UInt32.max))
            c.rcvNxt = seq &+ 1
            c.sndUna = c.iss; c.sndNxt = c.iss
            c.window = win
            // ゲストの MSS（オプション）
            var i = 20
            while i < off {
                let kind = b[i]
                if kind == 0 { break }
                if kind == 1 { i += 1; continue }
                guard i + 1 < off else { break }
                let l = Int(b[i + 1])
                if kind == 2, l == 4, i + 3 < off { c.mss = min(1460, Int(b[i + 2]) << 8 | Int(b[i + 3])) }
                i += max(2, l)
            }
            tcps[key] = c
            stats.tcpOpened += 1
            if debug { log?("[ネット] TCP 開く \(host):\(dport)") }
            c.sock = factory.tcp(host: host, port: dport, queue: queue, onReady: { [weak self, weak c] in
                guard let self, let c, c.state == .connecting else { return }
                c.state = .synSent
                self.sendTCP(c, flags: SYN | ACK, seq: c.iss, mssOption: true)
                c.sndNxt = c.iss &+ 1
                c.lastProgress = Date()
                self.readIfRoom(c)
            }, onData: { [weak self, weak c] d in
                guard let self, let c else { return }
                c.reading = false
                if self.debug && c.totalIn == 0 { self.log?("[ネット] TCP 受信 \(UserNet.ipString(c.key.dst)):\(c.key.dport) \(d.count) バイト: \(UserNet.preview(d))") }
                c.totalIn += d.count
                c.buf.append(d)
                c.lastActivity = Date()
                self.pump(c)
                self.readIfRoom(c)
            }, onClose: { [weak self, weak c] error in
                guard let self, let c else { return }
                c.reading = false
                if c.state == .connecting || (error && c.state != .established) {
                    // つながらなかった
                    self.sendRST(src: UserNet.guestIP, dst: c.key.dst, sport: c.key.sport, dport: c.key.dport, seq: c.iss &+ 1, ack: c.rcvNxt)
                    self.remove(c)
                    return
                }
                c.remoteEOF = true
                self.pump(c)
            })
            return
        }

        c.lastActivity = Date()
        if flags & RST != 0 { remove(c, "ゲストの RST"); return }
        if flags & SYN != 0 {
            // SYN の送り直し: SYN+ACK を送り直す
            if c.state == .synSent { sendTCP(c, flags: SYN | ACK, seq: c.iss, mssOption: true) }
            return
        }
        if flags & ACK != 0 {
            let acked = ack &- c.sndUna
            let inFlight = c.sndNxt &- c.sndUna
            if acked > 0 && acked <= inFlight {
                var n = Int(acked)
                if c.state == .synSent {
                    c.state = .established; n -= 1      // SYN の分
                    if debug { log?("[ネット] TCP 確立 \(UserNet.ipString(c.key.dst)):\(c.key.dport)") }
                }
                let dataAcked = min(n, c.buf.count)
                if dataAcked > 0 { c.buf.removeFirst(dataAcked) }
                c.sndUna = ack
                c.lastProgress = Date()
                c.retries = 0
                readIfRoom(c)
            }
            c.window = win
        }
        if c.state == .synSent || c.state == .connecting { return }
        // データ
        var needAck = false
        if !payload.isEmpty {
            if seq == c.rcvNxt {
                c.sock?.send(Data(payload))
                if debug && c.totalOut == 0 { log?("[ネット] TCP 送信 \(UserNet.ipString(c.key.dst)):\(c.key.dport) \(payload.count) バイト: \(UserNet.preview(Data(payload)))") }
                c.totalOut += payload.count
                c.rcvNxt &+= UInt32(payload.count)
            }
            needAck = true
        }
        if flags & FIN != 0 && seq &+ UInt32(payload.count) == c.rcvNxt && !c.guestFIN {
            c.guestFIN = true
            c.rcvNxt &+= 1
            c.sock?.finish()
            needAck = true
        }
        let before = c.sndNxt
        pump(c)
        if needAck && c.sndNxt == before { sendTCP(c, flags: ACK, seq: c.sndNxt) }
        checkDone(c)
    }

    /// 外から来たデータを、ゲストの窓の分だけ送る。外が閉じていて全部送ったら FIN
    private func pump(_ c: TCPConn) {
        guard c.state == .established else { return }
        let PSH: UInt8 = 8, ACK: UInt8 = 16, FIN: UInt8 = 1
        while true {
            let sent = Int(c.sndNxt &- c.sndUna)
            if c.finSent { break }
            let unsent = c.buf.count - sent
            if unsent <= 0 {
                if c.remoteEOF {
                    sendTCP(c, flags: FIN | ACK, seq: c.sndNxt)
                    c.sndNxt &+= 1
                    c.finSent = true
                    c.lastProgress = Date()
                }
                break
            }
            let room = Int(c.window) - sent
            if room <= 0 { break }
            let n = min(unsent, c.mss, room)
            let start = c.buf.startIndex + sent
            sendTCP(c, flags: ACK | PSH, seq: c.sndNxt, payload: ArraySlice(c.buf[start..<(start + n)]))
            c.sndNxt &+= UInt32(n)
        }
        checkDone(c)
    }

    private func readIfRoom(_ c: TCPConn) {
        guard !c.reading, !c.remoteEOF, c.state == .established || c.state == .synSent,
              c.buf.count < UserNet.maxBuffered, let s = c.sock else { return }
        c.reading = true
        s.readMore()
    }

    private func checkDone(_ c: TCPConn) {
        // 両方が閉じて、こちらの FIN も受け取ってもらえたら終わり
        if c.guestFIN && c.finSent && c.sndUna == c.sndNxt { remove(c, "両方閉じた") }
    }

    private func remove(_ c: TCPConn, _ why: String = "") {
        if c.state == .closed { return }
        if debug { log?("[ネット] TCP 終わり \(UserNet.ipString(c.key.dst)):\(c.key.dport) \(why) 受信 \(c.totalIn) 送達 \(c.sndUna &- c.iss) 残り \(c.buf.count) EOF \(c.remoteEOF) FIN \(c.finSent)/\(c.guestFIN)") }
        c.state = .closed
        c.sock?.close()
        c.sock = nil
        if tcps[c.key] === c { tcps[c.key] = nil }
    }

    // MARK: 時間で見るもの（送り直しと、古い接続の片付け）

    private func tick() {
        let now = Date()
        for c in Array(tcps.values) {
            if c.state == .synSent && now.timeIntervalSince(c.lastProgress) > 1 {
                c.retries += 1
                if c.retries > 6 { remove(c); continue }
                sendTCP(c, flags: 2 | 16, seq: c.iss, mssOption: true)
                c.lastProgress = now
            } else if c.state == .established && c.sndNxt != c.sndUna && now.timeIntervalSince(c.lastProgress) > 1 {
                // 受け取りの返事が来ない: 先頭から送り直す
                c.retries += 1
                if c.retries > 10 {
                    sendRST(src: UserNet.guestIP, dst: c.key.dst, sport: c.key.sport, dport: c.key.dport, seq: c.sndNxt, ack: c.rcvNxt)
                    remove(c); continue
                }
                c.sndNxt = c.sndUna
                c.finSent = false
                c.lastProgress = now
                if c.window == 0 { c.window = 1 }       // 窓が 0 のままなら 1 バイトだけ送って様子を見る
                pump(c)
            } else if now.timeIntervalSince(c.lastActivity) > 600 {
                remove(c)
            }
        }
        for (k, u) in udps where now.timeIntervalSince(u.last) > 60 {
            u.sock?.close()
            udps[k] = nil
        }
    }
}
