import XCTest
@testable import Kit

final class KitTests: XCTestCase {
    func testVersion() { XCTAssertEqual(Kit.version(), "1.0") }
}
