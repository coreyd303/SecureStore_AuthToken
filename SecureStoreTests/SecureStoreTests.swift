/// Copyright (c) 2019 Razeware LLC
/// 
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
/// 
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
/// 
/// Notwithstanding the foregoing, you may not use, copy, modify, merge, publish,
/// distribute, sublicense, create a derivative work, and/or sell copies of the
/// Software in any work that is designed, intended, or marketed for pedagogical or
/// instructional purposes related to programming, coding, application development,
/// or information technology.  Permission for such use, copying, modification,
/// merger, publication, distribution, sublicensing, creation of derivative works,
/// or sale is expressly withheld.
/// 
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
/// THE SOFTWARE.

import XCTest
@testable import SecureStore

class SecureStoreTests: XCTestCase {

  var secureStoreWithAuthToken: SecureStore!
  var stubAuthToken: AuthToken!

  override func setUp() {
    super.setUp()
    let authTokenQueryable = AuthTokenQueryable(service: "someService")
    secureStoreWithAuthToken = SecureStore(secureStoreQueryable: authTokenQueryable)
    stubAuthToken = AuthToken(token: "TOKEN", expires: 123456)
  }

  override func tearDown() {
    try? secureStoreWithAuthToken.removeAllValues()

    super.tearDown()
  }

  func testSaveAuthToken() {
    do {
      try secureStoreWithAuthToken.setAuthToken(stubAuthToken, for: "authToken")
    } catch(let error) {
      XCTFail("Saving authToken failed with \(error.localizedDescription).")
    }
  }

  func testReadAuthToken() {
    do {
      try secureStoreWithAuthToken.setAuthToken(stubAuthToken, for: "authToken")
      let expectedToken = try secureStoreWithAuthToken.getAuthToken(for: "authToken")

      XCTAssertEqual("TOKEN", expectedToken?.token)
    } catch (let error) {
      XCTFail("Reading authToken failed with \(error.localizedDescription).")
    }
  }

  // 3
  func testUpdateAuthToken() {
    do {
      try secureStoreWithAuthToken.setAuthToken(stubAuthToken, for: "authToken")
      let newToken = AuthToken(token: "SOMETHING ELSE", expires: 123456)
      try secureStoreWithAuthToken.setAuthToken(newToken, for: "authToken")

      let expectedToken = try secureStoreWithAuthToken.getAuthToken(for: "authToken")
      XCTAssertEqual("SOMETHING ELSE", expectedToken?.token)
    } catch (let error) {
      XCTFail("Updating authToken failed with \(error.localizedDescription).")
    }
  }

  // 4
  func testRemoveAuthToken() {
    do {
      try secureStoreWithAuthToken.setAuthToken(stubAuthToken, for: "authToken")
      try secureStoreWithAuthToken.removeValue(for: "authToken")

      XCTAssertNil(try secureStoreWithAuthToken.getAuthToken(for: "authToken"))
    } catch (let error) {
      XCTFail("Saving authToken failed with \(error.localizedDescription).")
    }
  }


  // 5
  func testRemoveAllAuthTokens() {
    do {
      try secureStoreWithAuthToken.setAuthToken(stubAuthToken, for: "authToken")
      let token2 = AuthToken(token: "ANOTHER", expires: 5678909)
      try secureStoreWithAuthToken.setAuthToken(token2, for: "authToken2")
      try secureStoreWithAuthToken.removeAllValues()

      XCTAssertNil(try secureStoreWithAuthToken.getAuthToken(for: "authToken"))
      XCTAssertNil(try secureStoreWithAuthToken.getAuthToken(for: "authToken2"))
    } catch (let error) {
      XCTFail("Removing authTokens failed with \(error.localizedDescription).")
    }
  }
}
