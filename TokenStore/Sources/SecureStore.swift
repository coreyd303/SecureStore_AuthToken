/// Copyright (c) 2018 Razeware LLC
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

import Foundation
import Security

public struct SecureStore {
  // MARK: - Properties

  let secureStoreQueryable: SecureStoreQueryable

  // MARK: - Initialization

  public init(secureStoreQueryable: SecureStoreQueryable) {
    self.secureStoreQueryable = secureStoreQueryable
  }

  // MARK: - Public

  public func setAuthToken(_ authToken: AuthToken, for userAccount: String) throws {
    /// Check if it can encode the value to store into a Data type. If that’s not possible, it throws a conversion error.
    guard let encodedAuth = try? PropertyListEncoder().encode(authToken) else {
      throw SecureStoreError.token2DataConversionError
    }

    /// Ask the secureStoreQueryable instance for the query to execute and append the account you’re looking for.
    var query = secureStoreQueryable.query
    query[String(kSecAttrAccount)] = userAccount

    /// Return the keychain item that matches the query.
    var status = SecItemCopyMatching(query as CFDictionary, nil)
    switch status {
    case errSecSuccess:
      /// If the query succeeds, it means a password for that account already exists. In this case, you replace the existing password’s value using SecItemUpdate(_:_:).
      var attributesToUpdate: [String: Any] = [:]
      attributesToUpdate[String(kSecValueData)] = encodedAuth

      status = SecItemUpdate(query as CFDictionary, attributesToUpdate as CFDictionary)
      if status != errSecSuccess {
        throw error(from: status)
      }
    case errSecItemNotFound:
      /// If it cannot find an item, the password for that account does not exist yet. You add the item by invoking SecItemAdd(_:_:).
      query[String(kSecValueData)] = encodedAuth
      status = SecItemAdd(query as CFDictionary, nil)
      if status != errSecSuccess {
        throw error(from: status)
      }
    default:
      throw error(from: status)
    }
  }
  
  public func getAuthToken(for userAccount: String) throws -> AuthToken? {
    /// Ask secureStoreQueryable for the query to execute. Besides adding the account you’re interested in, this enriches the query with other attributes and their related values. In particular, you’re asking it to return a single result, to return all the attributes associated with that specific item and to give you back the unencrypted data as a result.
    var query = secureStoreQueryable.query
    query[String(kSecMatchLimit)] = kSecMatchLimitOne
    query[String(kSecReturnAttributes)] = kCFBooleanTrue
    query[String(kSecReturnData)] = kCFBooleanTrue
    query[String(kSecAttrAccount)] = userAccount

    /// Use SecItemCopyMatching(_:_:) to perform the search. On completion, queryResult will contain a reference to the found item, if available. withUnsafeMutablePointer(to:_:) gives you access to an UnsafeMutablePointer that you can use and modify inside the closure to store the result.
    var queryResult: AnyObject?
    let status = withUnsafeMutablePointer(to: &queryResult) {
      SecItemCopyMatching(query as CFDictionary, $0)
    }

    switch status {
    case errSecSuccess:
      /// If the query succeeds, it means that it found an item. Since the result is represented by a dictionary that contains all the attributes you’ve asked for, you need to extract the data first and then decode it into a Data type.
      guard let queriedItem = queryResult as? [String: Any],
            let tokenData = queriedItem[String(kSecValueData)] as? Data,
            let authToken = try? PropertyListDecoder().decode(AuthToken.self, from: tokenData) else {
          throw SecureStoreError.data2tokenConversionError
      }

      return authToken
    case errSecItemNotFound:
      /// If an item is not found, return a nil value.
      return nil
    default:
      throw error(from: status)
    }
  }
  
  public func removeValue(for userAccount: String) throws {
    var query = secureStoreQueryable.query
    query[String(kSecAttrAccount)] = userAccount

    let status = SecItemDelete(query as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw error(from: status)
    }
  }
  
  public func removeAllValues() throws {
    let query = secureStoreQueryable.query

    let status = SecItemDelete(query as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw error(from: status)
    }
  }

  // MARK: - Private

  private func error(from status: OSStatus) -> SecureStoreError {
    let message = SecCopyErrorMessageString(status, nil) as String? ?? NSLocalizedString("Unhandled Error", comment: "")
    return SecureStoreError.unhandledError(message: message)
  }
}
