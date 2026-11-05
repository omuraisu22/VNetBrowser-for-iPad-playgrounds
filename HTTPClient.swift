import Foundation

// MARK: - 自作の TCP/IP（GuestStack）の上の、ごく小さな http / https の取得
//
// 1. 名前を DNS（10.0.2.3）で IP アドレスにする
// 2. TCP でつなぐ（https なら、その上で TLS）
// 3. 「GET … HTTP/1.1」を送り、相手が閉じるまで受け取る（Connection: close）
// 4. 返事を「状態・ヘッダ・中身」に分ける（chunked も戻す）。リダイレクトは 5 回まで追いかける

struct HTTPResult: Sendable {
    var status: Int
    var headers: [(String, String)]
    var body: Data
    var url: URL
    func header(_ name: String) -> String? { headers.first { $0.0.lowercased() == name.lowercased() }?.1 }
}

final class HTTPFetch: @unchecked Sendable {
    let stack: GuestStack
    private var url: URL
    private let done: (Result<HTTPResult, FetchError>) -> Void
    private var redirects = 0
    private var raw = Data()
    private var tcp: GuestTCP?
    #if canImport(Security) && os(iOS)
    private var tls: TLSStream?
    #endif
    private var finished = false

    struct FetchError: Error, Sendable, CustomStringConvertible { let description: String }

    init(stack: GuestStack, url: URL, done: @escaping (Result<HTTPResult, FetchError>) -> Void) {
        self.stack = stack
        self.url = url
        self.done = done
    }

    /// 始める（stack.queue の上で呼ぶ）
    func start() {
        guard let host = url.host, let scheme = url.scheme?.lowercased(), scheme == "http" || scheme == "https" else {
            fail("http か https のアドレスを入れてください"); return
        }
        #if !(canImport(Security) && os(iOS))
        if scheme == "https" { fail("この環境では https を使えません"); return }
        #endif
        let port = UInt16(url.port ?? (scheme == "https" ? 443 : 80))
        raw = Data()
        stack.resolve(host) { [weak self] ip in
            guard let self, !self.finished else { return }
            guard let ip else { self.fail("名前が見つかりません: \(host)"); return }
            self.open(ip: ip, port: port, host: host, https: scheme == "https")
        }
    }

    private func requestBytes(host: String) -> Data {
        let comps = URLComponents(url: url, resolvingAgainstBaseURL: false)
        var path = comps?.percentEncodedPath ?? "/"
        if path.isEmpty { path = "/" }
        if let q = comps?.percentEncodedQuery { path += "?" + q }
        let hostHeader = url.port.map { "\(host):\($0)" } ?? host
        let req = "GET \(path) HTTP/1.1\r\nHost: \(hostHeader)\r\n"
            + "User-Agent: Mozilla/5.0 (iPad; VNetBrowser) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile Safari/604.1\r\n"
            + "Accept: */*\r\nAccept-Language: ja,en;q=0.8\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
        return Data(req.utf8)
    }

    private func open(ip: [UInt8], port: UInt16, host: String, https: Bool) {
        let req = requestBytes(host: host)
        #if canImport(Security) && os(iOS)
        if https {
            guard let t = TLSStream(host: host) else { fail("TLS を用意できません"); return }
            tls = t
            t.onReady = { [weak self, weak t] in
                self?.stack.trace?("TLS つながった（\(host)）")
                t?.write(req)
            }
            t.onData = { [weak self] d in self?.raw.append(d) }
            t.onClosed = { [weak self] err in
                guard let self else { return }
                if let err, self.raw.isEmpty { self.fail(err) } else { self.complete() }
            }
            tcp = stack.connect(ip, port, handler: .init(
                connected: { [weak self] in guard let self, let tc = self.tcp else { return }; self.tls?.attach(tc) },
                data: { [weak self] d in self?.tls?.tcpData(d) },
                closed: { [weak self] err in self?.tls?.tcpClosed(err) }))
            return
        }
        #endif
        tcp = stack.connect(ip, port, handler: .init(
            connected: { [weak self] in self?.tcp?.write(req) },
            data: { [weak self] d in self?.raw.append(d) },
            closed: { [weak self] err in
                guard let self else { return }
                if let err, self.raw.isEmpty { self.fail(err) } else { self.complete() }
            }))
    }

    private func fail(_ s: String) {
        if finished { return }
        finished = true
        done(.failure(FetchError(description: s)))
    }

    private func complete() {
        if finished { return }
        guard let r = HTTPFetch.parse(raw, url: url) else { fail("返事を読めませんでした（\(raw.count) バイト）"); return }
        if (300...399).contains(r.status), let loc = r.header("Location"), redirects < 5,
           let next = URL(string: loc, relativeTo: url)?.absoluteURL {
            redirects += 1
            stack.trace?("↪ \(r.status) → \(next.absoluteString)")
            url = next
            tcp = nil
            #if canImport(Security) && os(iOS)
            tls = nil
            #endif
            start()
            return
        }
        finished = true
        done(.success(r))
    }

    /// 「HTTP/1.1 200 OK\r\nヘッダ…\r\n\r\n中身」を分ける
    static func parse(_ raw: Data, url: URL) -> HTTPResult? {
        guard let end = raw.range(of: Data("\r\n\r\n".utf8)) else { return nil }
        let head = String(decoding: raw[raw.startIndex..<end.lowerBound], as: UTF8.self)
        var lines = head.components(separatedBy: "\r\n")
        let statusLine = lines.removeFirst().split(separator: " ")
        guard statusLine.count >= 2, let status = Int(statusLine[1]) else { return nil }
        var headers: [(String, String)] = []
        for l in lines {
            guard let c = l.firstIndex(of: ":") else { continue }
            headers.append((String(l[..<c]).trimmingCharacters(in: .whitespaces), String(l[l.index(after: c)...]).trimmingCharacters(in: .whitespaces)))
        }
        var body = Data(raw[end.upperBound...])
        if headers.contains(where: { $0.0.lowercased() == "transfer-encoding" && $0.1.lowercased().contains("chunked") }) {
            body = dechunk(body)
            headers.removeAll { $0.0.lowercased() == "transfer-encoding" }
        }
        return HTTPResult(status: status, headers: headers, body: body, url: url)
    }

    static func dechunk(_ d: Data) -> Data {
        let b = [UInt8](d)
        var out = Data()
        var i = 0
        while i < b.count {
            var j = i
            while j + 1 < b.count && !(b[j] == 13 && b[j + 1] == 10) { j += 1 }
            guard j + 1 < b.count else { break }
            let sizeText = String(decoding: b[i..<j], as: UTF8.self).split(separator: ";").first.map(String.init) ?? ""
            guard let n = Int(sizeText.trimmingCharacters(in: .whitespaces), radix: 16) else { break }
            i = j + 2
            if n == 0 { break }
            guard i + n <= b.count else { out.append(contentsOf: b[i...]); break }
            out.append(contentsOf: b[i..<(i + n)])
            i += n + 2
        }
        return out
    }
}
