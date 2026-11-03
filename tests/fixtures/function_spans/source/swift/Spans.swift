import Foundation

let limit = 4 // ANCHOR:none

struct Store {
    var items: [String]

    func count(prefix: String) -> Int { // BEGIN:count
        let kept = items.filter { item in
            item.hasPrefix(prefix) // ANCHOR:count
        }
        return kept.count // ANCHOR:count
    } // END:count
}

func helper(_ value: Int) -> Int { // BEGIN:helper
    return value * 2 // ANCHOR:helper
} // END:helper
