import SwiftUI
import WebKit

// MARK: - 画面: 自作の通信（virtio-net → 小さなルーター）で読んだページを表示するブラウザ
//
// WKWebView には「vnets://…」（https）・「vnet://…」（http）という自分用のアドレスで読ませる。
// そのアドレスの読み込みは全部 VNetScheme が引き受けて、VNetMachine（自作の TCP/IP）で取ってくる。
// ・ページの中の「https://…」の部品（画像・CSS など）も、HTML と CSS を書き換えて自作の通信で読む
// ・それでも直接読もうとするもの（JavaScript が作るアドレスなど）は止める（実験なので、混ざらないように）

@MainActor
final class BrowserModel: NSObject, ObservableObject, WKNavigationDelegate {
    @Published var address = "https://example.com/"
    @Published var logText = ""
    @Published var status = "準備中…"
    @Published var pageTitle = ""
    let webView: WKWebView
    let machine = VNetMachine(factory: NWUserNetFactory())
    private let scheme = VNetScheme()
    private var logLines: [String] = []
    private var timer: Timer?

    override init() {
        let config = WKWebViewConfiguration()
        config.setURLSchemeHandler(scheme, forURLScheme: "vnet")
        config.setURLSchemeHandler(scheme, forURLScheme: "vnets")
        webView = WKWebView(frame: .zero, configuration: config)
        super.init()
        scheme.machine = machine
        scheme.model = self
        webView.navigationDelegate = self
        // ブラウザが自分で外へ読みに行くのを止める（自作の通信だけで読む実験のため）
        let rules = #"[{"trigger":{"url-filter":"^https?://"},"action":{"type":"block"}}]"#
        WKContentRuleListStore.default().compileContentRuleList(forIdentifier: "vnet-only", encodedContentRuleList: rules) { [weak self] list, _ in
            let model = self
            if let list { Task { @MainActor in model?.webView.configuration.userContentController.add(list) } }
        }
        let m = machine
        machine.log = { [weak self] s in
            let model = self
            Task { @MainActor in model?.addLog(s) }
        }
        m.boot()
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            let model = self
            Task { @MainActor in model?.refreshStatus() }
        }
    }

    func addLog(_ s: String) {
        logLines.append(s)
        if logLines.count > 300 { logLines.removeFirst(logLines.count - 300) }
        logText = logLines.joined(separator: "\n")
    }

    func refreshStatus() {
        let ip = machine.stack.ready ? "IP \(UserNet.ipString(machine.stack.ip))" : "IP をもらっています…"
        status = "\(ip)・\(machine.stats())"
    }

    /// https://… → vnets://…、http://… → vnet://…
    static func toVNet(_ u: URL) -> URL? {
        guard var c = URLComponents(url: u, resolvingAgainstBaseURL: true) else { return nil }
        switch c.scheme?.lowercased() {
        case "https": c.scheme = "vnets"
        case "http": c.scheme = "vnet"
        case "vnet", "vnets": break
        default: return nil
        }
        return c.url
    }

    static func toReal(_ u: URL) -> URL? {
        guard var c = URLComponents(url: u, resolvingAgainstBaseURL: true) else { return nil }
        switch c.scheme?.lowercased() {
        case "vnets": c.scheme = "https"
        case "vnet": c.scheme = "http"
        default: return nil
        }
        return c.url
    }

    func go() {
        var text = address.trimmingCharacters(in: .whitespaces)
        if !text.contains("://") { text = "https://" + text }
        guard let u = URL(string: text), let v = BrowserModel.toVNet(u) else { addLog("アドレスが正しくありません"); return }
        addLog("―― \(text) を開きます ――")
        webView.load(URLRequest(url: v))
    }

    // リンクを押したとき: https:// などのアドレスなら、自作の通信のアドレスに直して開き直す
    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction) async -> WKNavigationActionPolicy {
        if let u = navigationAction.request.url, let s = u.scheme?.lowercased(), s == "http" || s == "https",
           navigationAction.targetFrame?.isMainFrame ?? true, let v = BrowserModel.toVNet(u) {
            webView.load(URLRequest(url: v))
            return .cancel
        }
        return .allow
    }

    func webView(_ webView: WKWebView, didCommit navigation: WKNavigation!) {
        if let u = webView.url, let r = BrowserModel.toReal(u) { address = r.absoluteString }
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        pageTitle = webView.title ?? ""
    }
}

/// vnet:// と vnets:// の読み込みを引き受ける（呼ばれるのは画面のスレッド）
final class VNetScheme: NSObject, WKURLSchemeHandler, @unchecked Sendable {
    var machine: VNetMachine?
    weak var model: BrowserModel?
    private var tasks: [ObjectIdentifier: WKURLSchemeTask] = [:]

    func webView(_ webView: WKWebView, start task: WKURLSchemeTask) {
        MainActor.assumeIsolated { self.start(task) }
    }

    func webView(_ webView: WKWebView, stop task: WKURLSchemeTask) {
        MainActor.assumeIsolated { _ = self.tasks.removeValue(forKey: ObjectIdentifier(task)) }
    }

    @MainActor private func start(_ task: WKURLSchemeTask) {
        guard let vurl = task.request.url, let real = BrowserModel.toReal(vurl), let machine else {
            task.didFailWithError(URLError(.badURL)); return
        }
        let id = ObjectIdentifier(task)
        tasks[id] = task
        let started = Date()
        machine.fetch(real) { [weak self] result in
            let me = self
            Task { @MainActor in me?.finish(id, vurl, real, result, started) }
        }
    }

    @MainActor private func finish(_ id: ObjectIdentifier, _ vurl: URL, _ real: URL, _ result: Result<HTTPResult, HTTPFetch.FetchError>, _ started: Date) {
        guard let task = tasks.removeValue(forKey: id) else { return }
        let ms = Int(Date().timeIntervalSince(started) * 1000)
        switch result {
        case .failure(let e):
            model?.addLog("✕ \(real.absoluteString)：\(e.description)")
            let html = "<html><body style='font:16px -apple-system;padding:20px'><h3>読めませんでした</h3><p>\(real.absoluteString)</p><p>\(e.description)</p></body></html>"
            respond(task, vurl, 502, "text/html; charset=utf-8", Data(html.utf8))
        case .success(let r):
            model?.addLog("✓ \(r.status) \(real.absoluteString)（\(r.body.count / 1024)KB・\(ms)ms）")
            var type = r.header("Content-Type") ?? "application/octet-stream"
            var body = r.body
            // HTML と CSS の中の https:// を vnets:// に書き換える（部品も自作の通信で読むため）
            let lower = type.lowercased()
            if lower.contains("text/html") || lower.contains("text/css") {
                var s = String(decoding: body, as: UTF8.self)
                for (from, to) in [("https://", "vnets://"), ("http://", "vnet://"), ("https:\\/\\/", "vnets:\\/\\/")] {
                    for q in ["\"", "'", "(", "=", " "] { s = s.replacingOccurrences(of: q + from, with: q + to) }
                }
                body = Data(s.utf8)
                if !lower.contains("charset") { type += "; charset=utf-8" }
            }
            // 移動した先のアドレスで表示する（相対アドレスがずれないように）
            let shown = r.url == real ? vurl : (BrowserModel.toVNet(r.url) ?? vurl)
            respond(task, shown, r.status, type, body)
        }
    }

    @MainActor private func respond(_ task: WKURLSchemeTask, _ url: URL, _ status: Int, _ type: String, _ body: Data) {
        let resp = HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1",
                                   headerFields: ["Content-Type": type, "Content-Length": String(body.count),
                                                  "Access-Control-Allow-Origin": "*"])!
        task.didReceive(resp)
        task.didReceive(body)
        task.didFinish()
    }
}

struct WebBox: UIViewRepresentable {
    let webView: WKWebView
    func makeUIView(context: Context) -> WKWebView { webView }
    func updateUIView(_ uiView: WKWebView, context: Context) {}
}

struct BrowserView: View {
    @StateObject private var model = BrowserModel()
    @State private var showLog = true

    var body: some View {
        VStack(spacing: 8) {
            HStack {
                Button { model.webView.goBack() } label: { Image(systemName: "chevron.backward") }
                Button { model.webView.goForward() } label: { Image(systemName: "chevron.forward") }
                TextField("アドレス", text: $model.address)
                    .textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .keyboardType(.URL)
                    .onSubmit { model.go() }
                Button("開く") { model.go() }.buttonStyle(.borderedProminent)
            }
            Text(model.status).font(.caption).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading)
            WebBox(webView: model.webView)
                .clipShape(RoundedRectangle(cornerRadius: 8))
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.secondary.opacity(0.3)))
            Toggle("通信のログ（virtio-net → ルーター）", isOn: $showLog).font(.caption)
            if showLog {
                ScrollViewReader { proxy in
                    ScrollView {
                        Text(model.logText)
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundStyle(Color.green)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .textSelection(.enabled)
                        Color.clear.frame(height: 1).id("end")
                    }
                    .frame(height: 180)
                    .background(Color.black)
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                    .onChange(of: model.logText) { proxy.scrollTo("end", anchor: .bottom) }
                }
            }
        }
        .padding()
    }
}
