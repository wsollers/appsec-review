import Foundation
import SQLite3

protocol Store {
    func save(_ value: String)
}

final class FileStore: Store {
    func save(_ value: String) {
        FileManager.default.createFile(atPath: value, contents: nil)
    }
}

final class MemoryStore: Store {
    var items: [String] = []
    func save(_ value: String) {
        items.append(value)
    }
}

func fetchRemote(_ url: URL) -> String {
    let body = try! String(contentsOf: url)
    return body
}

func buildQuery(_ name: String) -> String {
    return "SELECT * FROM users WHERE name = '" + name + "'"
}

func runQuery(_ db: OpaquePointer?, _ url: URL) {
    let query = buildQuery(fetchRemote(url))
    sqlite3_exec(db, query, nil, nil, nil)
}

func persist(_ store: Store) {
    let args = CommandLine.arguments
    store.save(args[1])
}

func runCommand() throws {
    let cmd = ProcessInfo.processInfo.environment["CMD"] ?? ""
    try Process.run(URL(fileURLWithPath: "/bin/sh"), arguments: ["-c", cmd])
}

func proxy(_ request: URL) {
    let target = URL(string: fetchRemote(request))!
    URLSession.shared.dataTask(with: target).resume()
}

func restore(_ url: URL) throws -> Any? {
    let blob = try Data(contentsOf: url)
    return try NSKeyedUnarchiver.unarchiveTopLevelObjectWithData(blob)
}

func readSafe(_ url: URL) -> Data? {
    let safe = URL(fileURLWithPath: fetchRemote(url)).resolvingSymlinksInPath()
    return FileManager.default.contents(atPath: safe.path)
}

func allocateBuffer(_ url: URL) {
    let count = Int(fetchRemote(url)) ?? 0
    if count < 64 {
        let checked = UnsafeMutablePointer<UInt8>.allocate(capacity: count)
        checked.deallocate()
    }
    let unchecked = UnsafeMutablePointer<UInt8>.allocate(capacity: count)
    unchecked.deallocate()
}

func notify(_ handler: (String) -> Void, _ message: String) {
    handler(message)
}

func filterItems(_ items: NSArray, _ url: URL) -> [Any] {
    let filter = fetchRemote(url)
    return items.filtered(using: NSPredicate(format: filter))
}
