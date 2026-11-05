import Foundation
#if canImport(Security)
import Security
#endif

// MARK: - https の暗号（TLS）を、自作の TCP の上で動かす
//
// iPad の普通の通信の部品（Network.framework）は、自分で作った TCP の上では TLS を使えない。
// そこで、古いけれど今も使える Apple の「SecureTransport」（SSLCreateContext など）を使う。
// これは「読む・書く」を自分で用意できるので、GuestTCP の上で TLS 1.2 を話せる。
// 証明書は iPad と同じ仕組みで確かめる（相手の名前も確かめる）。
//
// 使い方: TLSStream を作って start() → ready で request を送る → data で中身が届く → closed

#if canImport(Security) && os(iOS)
final class TLSStream: @unchecked Sendable {
    let host: String
    private let ctx: SSLContext
    private var tcp: GuestTCP?
    private var inbox = Data()
    private var tcpClosed = false
    private var handshaking = true
    private var pendingWrite = Data()
    private var done = false
    var onReady: (() -> Void)?
    var onData: ((Data) -> Void)?
    var onClosed: ((String?) -> Void)?

    init?(host: String) {
        self.host = host
        guard let c = SSLCreateContext(nil, .clientSide, .streamType) else { return nil }
        ctx = c
        SSLSetIOFuncs(ctx, tlsRead, tlsWrite)
        SSLSetProtocolVersionMax(ctx, .tlsProtocol12)
        _ = host.withCString { SSLSetPeerDomainName(ctx, $0, strlen($0)) }
    }

    /// TCP がつながったら呼ぶ
    func attach(_ t: GuestTCP) {
        tcp = t
        SSLSetConnection(ctx, Unmanaged.passUnretained(self).toOpaque())
        drive()
    }

    /// TCP から届いたもの
    func tcpData(_ d: Data) {
        inbox.append(d)
        drive()
    }

    func tcpClosed(_ error: String?) {
        tcpClosed = true
        drive()
        if !done { finish(error ?? (handshaking ? "TLS の途中で切れました" : nil)) }
    }

    /// 暗号にして送る（つながる前なら、つながってから送る）
    func write(_ d: Data) {
        if handshaking { pendingWrite.append(d); return }
        var processed = 0
        _ = d.withUnsafeBytes { SSLWrite(ctx, $0.baseAddress, d.count, &processed) }
    }

    private func finish(_ error: String?) {
        if done { return }
        done = true
        tcp?.abort()
        onClosed?(error)
    }

    /// 進められるところまで進める（握手 → 読む）
    private func drive() {
        if done { return }
        if handshaking {
            let st = SSLHandshake(ctx)
            if st == errSSLWouldBlock { return }
            if st != errSecSuccess {
                finish("TLS の握手に失敗（\(st)）" + (st == errSSLXCertChainInvalid || st == -9807 ? "：証明書を確かめられません" : ""))
                return
            }
            handshaking = false
            onReady?()
            if !pendingWrite.isEmpty { let w = pendingWrite; pendingWrite = Data(); write(w) }
        }
        var buf = [UInt8](repeating: 0, count: 16384)
        while true {
            var n = 0
            let st = buf.withUnsafeMutableBytes { SSLRead(ctx, $0.baseAddress!, $0.count, &n) }
            if n > 0 { onData?(Data(buf[0..<n])) }
            if st == errSSLWouldBlock { if tcpClosed && inbox.isEmpty { finish(nil) }; return }
            if st == errSSLClosedGraceful || st == errSSLClosedNoNotify || st == errSSLClosedAbort { finish(nil); return }
            if st != errSecSuccess { finish("TLS の読み込みに失敗（\(st)）"); return }
        }
    }

    // SecureTransport から呼ばれる「読む・書く」
    fileprivate func readInto(_ p: UnsafeMutableRawPointer, _ want: Int) -> (Int, OSStatus) {
        if inbox.isEmpty { return (0, tcpClosed ? errSSLClosedNoNotify : errSSLWouldBlock) }
        let n = min(want, inbox.count)
        inbox.copyBytes(to: p.assumingMemoryBound(to: UInt8.self), count: n)
        inbox.removeFirst(n)
        return (n, n < want ? errSSLWouldBlock : errSecSuccess)
    }

    fileprivate func writeFrom(_ p: UnsafeRawPointer, _ n: Int) -> OSStatus {
        guard let t = tcp else { return errSSLClosedAbort }
        t.write(Data(bytes: p, count: n))
        return errSecSuccess
    }
}

private func tlsRead(_ conn: SSLConnectionRef, _ data: UnsafeMutableRawPointer, _ length: UnsafeMutablePointer<Int>) -> OSStatus {
    let s = Unmanaged<TLSStream>.fromOpaque(conn).takeUnretainedValue()
    let (n, st) = s.readInto(data, length.pointee)
    length.pointee = n
    return st
}

private func tlsWrite(_ conn: SSLConnectionRef, _ data: UnsafeRawPointer, _ length: UnsafeMutablePointer<Int>) -> OSStatus {
    let s = Unmanaged<TLSStream>.fromOpaque(conn).takeUnretainedValue()
    return s.writeFrom(data, length.pointee)
}
#endif
