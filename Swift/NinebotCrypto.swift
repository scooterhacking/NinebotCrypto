//
//  NinebotCrypto.swift
//  NinebotCrypto
//
//  Created by Robert Trencheny on 2/23/20.
//  Copyright © 2020 Robert Trencheny. All rights reserved.
//

import Foundation
import CryptoSwift

class NinebotCrypto {
    private var firmwareData: [UInt8] = [0x97, 0xCF, 0xB8, 0x02, 0x84, 0x41, 0x43, 0xDE, 0x56, 0x00, 0x2B, 0x3B, 0x34, 0x78, 0x0A, 0x5D]
    private var randomBLEData: [UInt8] = [] {
       didSet {
           print("Set randomBLEData", randomBLEData.toPrettyHexString())
       }
   } // 16
    private var randomAppData: [UInt8] = [UInt8]() {
        didSet {
            print("Set randomAppData", randomAppData.toPrettyHexString())
        }
    } // 16
    private var shaKey: [UInt8] = [UInt8]() // 16
    private var messageCount: UInt32 = 0
    private var deviceName: String!
    private var serialNumber: String?

    public init() {}

    public init(_ deviceName: String) {
        self.SetName(deviceName)
    }

    public func SetName(_ deviceName: String) {
        self.deviceName = deviceName
        CalcSha1Key(Array<UInt8>(deviceName.utf8), firmwareData)
    }

    public func Reset() {
        guard let existingName = self.deviceName else { return }
        self.randomBLEData = [UInt8](repeating: 0, count: 8)
        self.randomAppData = [UInt8](repeating: 0, count: 8)
        self.shaKey = [UInt8]()
        self.messageCount = 0
        self.SetName(existingName)
    }

    public func Decrypt(_ encryptedData: [UInt8]) -> [UInt8]? {
        if encryptedData[0] != 0x5A || encryptedData[1] != 0xA5 {
            print("Refusing to attempt decryption of invalid payload!", encryptedData.toHexString())
            return nil
        }
        var decrypted: [UInt8] = [UInt8]()
        decrypted = BlockCopy(encryptedData, 0, decrypted, 0, 3)
        var newMessageCount: UInt32 = messageCount
        if ((newMessageCount & 0x0008000) > 0 && (encryptedData[encryptedData.count - 2] >> 7) == 0) {
            newMessageCount += 0x0010000
        }
        newMessageCount = (newMessageCount & 0xFFFF0000) + (UInt32)(encryptedData[encryptedData.count - 2] << 8) + UInt32(encryptedData[encryptedData.count - 1])
        let payloadLength = encryptedData.count - 9
        var payload: [UInt8] = []
        payload = BlockCopy(encryptedData, 3, payload, 0, payloadLength)
        if newMessageCount == 0 {
            guard let decryptedPayload = CryptoFirst(payload) else {
                print("Failed to encrypt payload to test equality during decryption of first message!")
                return nil
            }
            guard let encryptedPayload = CryptoFirst(decryptedPayload) else {
                print("Failed to encrypt decrypted payload to test equality during decryption of first message!")
                return nil
            }
            if encryptedPayload != payload {
                print("Decryption equality test failed during decryption of first message! Payload: \(payload.toHexString()), Decrypted Payload: \(decryptedPayload.toHexString()), Encrypted Payload: \(encryptedPayload.toHexString())")
                return nil
            }
            payload = decryptedPayload
            decrypted = BlockCopy(payload, 0, decrypted, 3, payload.count)
            if (decrypted[0] == 0x5A &&
                decrypted[1] == 0xA5 &&
                decrypted[2] == 0x1E &&
                decrypted[3] == 0x21 &&
                decrypted[4] == 0x3E &&
                decrypted[5] == 0x5B ) {
                self.serialNumber = String(data: Data(decrypted[decrypted.count - 15...decrypted.count - 1]), encoding: .ascii)
                print("Found serial number", self.serialNumber ?? "NOT FOUND")

                randomBLEData = BlockCopy(decrypted, 7, randomBLEData, 0, 16)
                CalcSha1Key(Array<UInt8>(deviceName.utf8), randomBLEData)
            }
        } else if (newMessageCount > 0 && newMessageCount > messageCount) {
            guard let decryptedPayload = CryptoNext(payload, newMessageCount) else {
                print("Failed to encrypt payload to test equality during decryption of after first message!")
                return nil
            }
            guard let encryptedPayload = CryptoNext(decryptedPayload, newMessageCount) else {
                print("Failed to encrypt decrypted payload to test equality during decryption of after first message!")
                return nil
            }
            if encryptedPayload != payload {
                print("Decryption equality test failed during decryption of after first message! Payload: \(payload.toHexString()), Decrypted Payload: \(decryptedPayload.toHexString()), Encrypted Payload: \(encryptedPayload.toHexString())")
                return nil
            }
            payload = decryptedPayload
            decrypted = BlockCopy(payload, 0, decrypted, 3, payload.count)
            if (decrypted[0] == 0x5A &&
                decrypted[1] == 0xA5 &&
                decrypted[2] == 0x00 &&
                decrypted[3] == 0x21 &&
                decrypted[4] == 0x3E &&
                decrypted[5] == 0x5C &&
                decrypted[6] == 0x01) {
                print("FILL TWO")
                CalcSha1Key(Array<UInt8>(randomAppData.prefix(16)), randomBLEData)
            }
            messageCount = newMessageCount
        }
        return decrypted
    }

    public func Encrypt(_ decryptedData: [UInt8]) -> [UInt8]? {
        if decryptedData[0] != 0x5A || decryptedData[1] != 0xA5 {
            print("Refusing to attempt encryption of invalid payload!", decryptedData.toHexString())
            return nil
        }
        var encrypted: [UInt8] = [UInt8](repeating: 0, count: 152) // 152
        encrypted = BlockCopy(decryptedData, 0, encrypted, 0, 3)
        let payloadLength = decryptedData.count - 3
        var payload: [UInt8] = [UInt8]() // payload_len
        payload = BlockCopy(decryptedData, 3, payload, 0, payloadLength)
        if messageCount == 0 {
            let crc = CalcCrcFirstMsg(payload)
            guard let firstPayload = CryptoFirst(payload) else {
                print("Failed to encrypt payload to test equality during encryption of first message!")
                return nil
            }
            payload = firstPayload
            encrypted = BlockCopy(payload, 0, encrypted, 3, payload.count)
            encrypted[payloadLength + 3] = 0
            encrypted[payloadLength + 4] = 0
            encrypted[payloadLength + 5] = crc[0]
            encrypted[payloadLength + 6] = crc[1]
            encrypted[payloadLength + 7] = 0
            encrypted[payloadLength + 8] = 0
            encrypted = Array(encrypted.prefix(payloadLength + 9))
            messageCount += 1
        } else {
            messageCount += 1
            guard let crc = CalcCrcNextMsg(decryptedData, messageCount) else {
                print("Failed to calculate CRC for next message")
                return nil
            }
            guard let nextPayload = CryptoNext(payload, messageCount) else {
                print("Failed to encrypt decrypted payload to test equality during encryption of after first message!")
                return nil
            }
            payload = nextPayload
            encrypted = BlockCopy(payload, 0, encrypted, 3, payload.count)
            encrypted[payloadLength + 3] = crc[0]
            encrypted[payloadLength + 4] = crc[1]
            encrypted[payloadLength + 5] = crc[2]
            encrypted[payloadLength + 6] = crc[3]
            encrypted[payloadLength + 7] = UInt8(((messageCount & 0x0000FF00) >> 8))
            encrypted[payloadLength + 8] = UInt8(((messageCount & 0x000000FF) >> 0))
            encrypted = Array(encrypted.prefix(payloadLength + 9))
            if (decryptedData[0] == 0x5A &&
                decryptedData[1] == 0xA5 &&
                decryptedData[2] == 0x10 &&
                decryptedData[3] == 0x3E &&
                decryptedData[4] == 0x21 &&
                decryptedData[5] == 0x5C &&
                decryptedData[6] == 0x00) {
                print("FILL THREE")
                randomAppData = BlockCopy(decryptedData, 7, randomAppData, 0, 16)
            }
        }
        return encrypted
    }

    private func CryptoFirst(_ inputData: [UInt8]) -> [UInt8]? {
        var result: [UInt8] = [UInt8]() // inputData.count
        var payloadLength = inputData.count
        var byteIndex = 0
        var xorData1: [UInt8] = [UInt8]() // 16
        var xorData2: [UInt8] = [UInt8]() // 16
        while payloadLength > 0 {
            let tempLength = (payloadLength <= 16 ? payloadLength : 16)
            xorData1 = BlockCopy(inputData, byteIndex, xorData1, 0, tempLength)
            guard let aes_key = AesEcbEncrypt(firmwareData, shaKey) else {
                print("Failed to get AES key during CryptoFirst!")
                return nil
            }
            xorData2 = BlockCopy(aes_key, 0, xorData2, 0, 16)
            let xorData: [UInt8] = xor(xorData1, xorData2)
            result = BlockCopy(xorData, 0, result, byteIndex, tempLength)
            payloadLength = payloadLength - Int(tempLength)
            byteIndex = byteIndex + tempLength
        }
        return result
    }

    private func CryptoNext(_ inputData: [UInt8], _ MsgIt: UInt32) -> [UInt8]? {
        var result: [UInt8] = [UInt8]() // inputData.count
        var encryptedData: [UInt8] = [UInt8](repeating: 0, count: 2) // 16
        encryptedData.insert(1, at: 0)
        encryptedData.insert(UInt8(((MsgIt & 0xFF000000) >> 24)), at: 1)
        encryptedData.insert(UInt8(((MsgIt & 0x00FF0000) >> 16)), at: 2)
        encryptedData.insert(UInt8(((MsgIt & 0x0000FF00) >> 8)), at: 3)
        encryptedData.insert(UInt8(((MsgIt & 0x000000FF) >> 0)), at: 4)
        encryptedData = BlockCopy(randomBLEData, 0, encryptedData, 5, 8)
        encryptedData.insert(0, at: 15)
        var payloadLength = inputData.count
        var byteIndex = 0
        var xorData1: [UInt8] = [UInt8](repeating: 0, count: 13) // 16
        var xorData2: [UInt8] = [UInt8]() // 16
        while payloadLength > 0 {
            encryptedData[15] += 1
            let tempLength = (payloadLength <= 16 ? payloadLength : 16)
            xorData1 = BlockCopy(inputData, byteIndex, xorData1, 0, tempLength)
            xorData1 = Array<UInt8>(xorData1.prefix(16))
            guard let aes_key = AesEcbEncrypt(encryptedData, shaKey) else {
                print("Failed to get AES key during CryptoNext!")
                return nil
            }
            xorData2 = BlockCopy(aes_key, 0, xorData2, 0, 16)
            let xorData: [UInt8] = xor(xorData1, xorData2)
            result = BlockCopy(xorData, 0, result, byteIndex, tempLength)
            payloadLength = payloadLength - tempLength
            byteIndex = byteIndex + tempLength
        }
        return result
    }

    private func CalcCrcFirstMsg(_ data: [UInt8]) -> [UInt8] {
        var crc: UInt16 = 0
        var i = 0
        while i < data.count {
            crc += UInt16(data[i])
            i += 1
        }
        crc = ~crc
        var ret: [UInt8] = [UInt8](repeating: 0, count: 2) // 2
        ret[0] = UInt8((crc & 0x00ff))
        ret[1] = UInt8(((crc >> 8) & 0x0ff))
        return ret
    }

    private func CalcCrcNextMsg(_ inputData: [UInt8], _ MsgIt: UInt32) -> [UInt8]? {
        var encryptedData: [UInt8] = [UInt8](repeating: 0, count: 2) // 16
        var payloadLength = inputData.count - 3
        var byteIndex = 3
        var xorData1: [UInt8] = [UInt8](repeating: 0, count: 13) // 16
        var xorData2: [UInt8] = [UInt8]() // 16
        var xorData: [UInt8] = [UInt8]()
        encryptedData.insert(89, at: 0)
        encryptedData.insert(UInt8(((MsgIt & 0xFF000000) >> 24)), at: 1)
        encryptedData.insert(UInt8(((MsgIt & 0x00FF0000) >> 16)), at: 2)
        encryptedData.insert(UInt8(((MsgIt & 0x0000FF00) >> 8)), at: 3)
        encryptedData.insert(UInt8(((MsgIt & 0x000000FF) >> 0)), at: 4)
        encryptedData = BlockCopy(randomBLEData, 0, encryptedData, 5, 8)
        encryptedData.insert(UInt8(payloadLength), at: 15)

        guard var aesKey = AesEcbEncrypt(encryptedData, shaKey) else {
            print("Failed to get first AES key during CalcCrcNextMsg!")
            return nil
        }

        xorData2 = BlockCopy(aesKey, 0, xorData2, 0, 16)
        xorData1 = BlockCopy(inputData, 0, xorData1, 0, 3)
        xorData = xor(xorData1, xorData2)

        guard let encXorData = AesEcbEncrypt(xorData, shaKey) else {
            print("Failed to get second AES key during CalcCrcNextMsg!")
            return nil
        }

        aesKey = encXorData

        xorData2.insert(contentsOf: aesKey[0..<16], at: 0)
        xorData2 = Array<UInt8>(xorData2.prefix(16))
        while payloadLength > 0 {
            let tempLength = (payloadLength <= 16 ? payloadLength : 16)
            xorData1 = [UInt8](repeating: 0, count: 16)

            xorData1 = BlockCopy(inputData, byteIndex, xorData1, 0, tempLength)
            xorData1 = Array<UInt8>(xorData1.prefix(16))

            xorData = xor(xorData1, xorData2)

            guard let encXorData = AesEcbEncrypt(xorData, shaKey) else {
                print("Failed to get AES key during rounds in CalcCrcNextMsg!")
                return nil
            }

            aesKey = encXorData

            xorData2.insert(contentsOf: aesKey[0..<16], at: 0)
            xorData2 = Array<UInt8>(xorData2.prefix(16))
            payloadLength = payloadLength - tempLength
            byteIndex = byteIndex + tempLength
        }
        encryptedData[0] = 1
        encryptedData[15] = 0
        guard let aesEncData = AesEcbEncrypt(encryptedData, shaKey) else {
            print("Failed to AES encrypt payload in CalcCrcNextMsg!")
            return nil
        }
        aesKey = aesEncData
        xorData1 = BlockCopy(aesKey, 0, xorData1, 0, 4)
        xorData2 = BlockCopy(xorData2, 0, xorData2, 0, 4)
        let ret = xor(xorData1, xorData2)

        print("CalcCrcNextMsg input = \"\(inputData.toHexString())\", output = \"\(ret.toHexString())\"")
        return ret
    }

    private func CalcSha1Key(_ sha1_data_1: [UInt8], _ sha1_data_2: [UInt8]) {
        var shaData = [UInt8](repeating: 0, count: 4)
        shaData.insert(contentsOf: sha1_data_1, at: 0)
        shaData.insert(contentsOf: sha1_data_2, at: 16)
        shaData = Array<UInt8>(shaData.prefix(32))
        let sha_hash: [UInt8] = shaData.sha1()
        shaKey = Array<UInt8>(sha_hash[0..<16])
    }

    private func AesEcbEncrypt(_ data: [UInt8], _ key: [UInt8]) -> [UInt8]? {
        do {
            return try AES(key: key, blockMode: ECB(), padding: .noPadding).encrypt(data)
        } catch {
            print("Failed to encrypt!", error)
            return nil
        }

    }

    // From CryptoSwift
    private func xor<T, V>(_ left: T, _ right: V) -> Array<UInt8> where T: RandomAccessCollection, V: RandomAccessCollection, T.Element == UInt8, T.Index == Int, V.Element == UInt8, V.Index == Int {
      let length = Swift.min(left.count, right.count)

      let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: length)
      buf.initialize(repeating: 0, count: length)
      defer {
        buf.deinitialize(count: length)
        buf.deallocate()
      }

      // xor
      for i in 0..<length {
        buf[i] = left[left.startIndex.advanced(by: i)] ^ right[right.startIndex.advanced(by: i)]
      }

      return Array(UnsafeBufferPointer(start: buf, count: length))
    }

    private func BlockCopy(_ src: [UInt8], _ srcOffset: Int, _ dst: [UInt8], _ dstOffset: Int, _ count: Int) -> [UInt8] {
        var retVal: [UInt8] = dst
        if src.count == 0 {
            return [UInt8]()
        }
        retVal.insert(contentsOf: src[srcOffset..<(srcOffset+count)], at: dstOffset)
        return retVal
    }
}
