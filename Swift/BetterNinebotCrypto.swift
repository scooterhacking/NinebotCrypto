// All of the implementations (primarily Swift and C#) on https://github.com/scooterhacking/NinebotCrypto were extremely useful in the creation of this library
//
//  NinebotCrypto.swift
//  NinebotCrypto
//
//  Created by Lex Nastin on 13/10/2023.
//

import Foundation
import CryptoSwift
import CryptoKit

class NinebotCrypto {
    // constants
    private let firmwareData = Data(hex: "97cfb802844143de56002b3b34780a5d")
    private let ninebotMagic = Data(hex: "5aa5")

    private let serialNumberMessage = Data(hex: "5aa51e213e5b")
    private let authRequestMessage =  Data(hex: "5aa5103e215c00")
    private let cryptoReadyMessage =  Data(hex: "5aa500213e5c01")

    // private vars
    private var randomBLEData: Data?
    private var randomAppData: Data?
    private var key: Data?
    private var messageCounter: Int
    private var deviceName: String?
    private var serialNumber: String?

    private var debug: Bool

    // public funcs
    public init(deviceName: String? = nil, debug: Bool = false) {
        self.messageCounter = -1
        self.deviceName = deviceName
        self.debug = debug

        if let deviceName = deviceName {
            self.setName(deviceName)
        }
    }

    public func setName(_ deviceName: String?) {
        guard var deviceName = deviceName else {
            self.deviceName = nil
            return
        }

        self.reset()

        if deviceName.count < 12 {
            deviceName = deviceName.padding(toLength: 12, withPad: "\0", startingAt: 0)
        }

        self.deviceName = deviceName
        self.calcKey(Data(deviceName.utf8), self.firmwareData)
    }

    public func reset() {
        self.randomBLEData = nil
        self.randomAppData = nil
        self.key = nil
        self.messageCounter = -1
        self.deviceName = nil
        self.serialNumber = nil
    }

    public func decrypt(_ encryptedData: Data) -> Data? {
        guard let key = self.key else {
            printDebug("Refusing to decrypt - key not set (did you run .setName()?)")
            return nil
        }

        guard encryptedData.count >= 9 else {
            printDebug("Refusing to decrypt - message too short")
            return nil
        }

        guard encryptedData.starts(with: self.ninebotMagic) else {
            printDebug("Refusing to decrypt - invalid magic (NinebotCrypto only supports 0x5AA5)")
            return nil
        }

        var decrypted = Data()
        decrypted.append(encryptedData[0..<3])
        var newMessageCounter = self.messageCounter
        if ((newMessageCounter & 0x0008000) > 0 && (encryptedData[encryptedData.count - 2] >> 7) == 0) {
            newMessageCounter += 0x0010000
        }
        newMessageCounter = (newMessageCounter & 0xffff0000) + (Int(encryptedData[encryptedData.count - 2]) << 8) + Int(encryptedData[encryptedData.count - 1])
        let payload = encryptedData[3..<encryptedData.count - 6]
        guard let decryptedPayload = self.crypto(data: payload, counter: newMessageCounter, key: key) else {
            self.printDebug("Failed to decrypt - refer to previous error(s)")
            return nil
        }
        guard let encryptedPayload = self.crypto(data: decryptedPayload, counter: newMessageCounter, key: key) else {
            self.printDebug("Failed to decrypt - reencryption for equality test failed, refer to previous error(s)")
            return nil
        }
        guard encryptedPayload == payload else {
            self.printDebug("Failed to decrypt - original payload doesn't equal reencrypted payload (internal failure)")
            return nil
        }
        decrypted.append(decryptedPayload)

        if newMessageCounter <= 0 {
            if decrypted.starts(with: self.serialNumberMessage) {
                guard decryptedPayload.count >= 34 else {
                    self.printDebug("Failed to extract serial number - decrypted payload too short (perhaps you didn't receive the full message?)")
                    return decrypted
                }
                let serialNumber = String(decoding: decryptedPayload.suffix(14), as: UTF8.self)
                let randomBLEData = decryptedPayload[4..<20]

                self.printDebug("Found serial number - \(serialNumber)")
                
                self.serialNumber = serialNumber
                self.randomBLEData = randomBLEData

                guard let deviceName = self.deviceName else {
                    self.printDebug("Failed to update encryption key - device name isn't set (did you run .setName()?)") // this should actually never happen as if we're here, self.key is set, and there is no way to change name (at least not that I intended) without setting self.key
                    return decrypted
                }
                self.calcKey(Data(deviceName.utf8), randomBLEData)
            }
        } else {
            if decrypted.starts(with: self.cryptoReadyMessage) {
                let randomAppData = self.randomAppData ?? Data(count: 8)
                let randomBLEData = self.randomBLEData ?? Data(count: 8)
                self.calcKey(randomAppData, randomBLEData)
                self.printDebug("Crypto ready")
            }
            
            if newMessageCounter > messageCounter {
                self.messageCounter = newMessageCounter
            } else {
                self.messageCounter += 1
            }
        }

        return decrypted
    }

    public func encrypt(_ decryptedData: Data) -> Data? {
        guard let key = self.key else {
            printDebug("Refusing to encrypt - key not set (did you run .setName()?)")
                return nil
        }

        guard decryptedData.count >= 3 else {
            printDebug("Refusing to encrypt - message too short")
                return nil
        }

        guard decryptedData.starts(with: self.ninebotMagic) else {
            printDebug("Refusing to encrypt - invalid magic (NinebotCrypto only supports 0x5AA5)")
                return nil
        }
        var encrypted = Data()
        encrypted.append(decryptedData[0..<3])
        let payload = decryptedData[3...]

        self.messageCounter += 1

        let crcPayload = self.messageCounter == 0 ? payload : decryptedData
        guard let crc = calcCrc(data: crcPayload, counter: self.messageCounter, key: key) else {
            self.printDebug("Failed to encrypt - can't calculate CRC (internal failure)")
            return nil
        }

        guard let encryptedPayload = crypto(data: payload, counter: self.messageCounter, key: key) else {
            self.printDebug("Failed to encrypt - refer to previous error(s)")
            return nil
        }

        encrypted.append(encryptedPayload)
        encrypted.append(crc)
        encrypted.append(UInt8((self.messageCounter & 0x0000FF00) >> 8))
        encrypted.append(UInt8((self.messageCounter & 0x000000FF) >> 0))

        if decryptedData.starts(with: self.authRequestMessage) {
            self.printDebug("Filling auth data")
            guard decryptedData.count >= 23 else {
                self.printDebug("Refusing to encrypt - attempting auth without random key (are you sure you added random 16 bytes of data to the end?)")
                return nil
            }
            self.randomAppData = decryptedData[7..<23]
        }

        return encrypted
    }

    // private funcs
    private func generateIv(counter: Int, crcData: Data? = nil) -> Data? {
        var iv = Data()
        let randomBLEData = self.randomBLEData ?? Data(count: 8)
        guard randomBLEData.count >= 8 else {
            self.printDebug("Refusing to do \(crcData == nil ? "crypto" : "crcCrypto") - randomBLEData is too short (internal failure)")
            return nil
        }
        let startByte: UInt8 = crcData == nil ? 0x01 : 0x59
        iv.append(startByte)
        var counter = counter
        iv.append(contentsOf: Data(bytes: &counter, count: 4).reversed())
        iv.append(randomBLEData.prefix(8))
        iv.append(Data(count: 2))
        let endByte: UInt8 = UInt8(crcData?.count ?? 0x04) - 3 // can't be bothered subtracting from only length. this is my way of doing length - 3 or 0x01 :D
        iv.append(endByte)

        return iv
    }

    private func crypto(data: Data, counter: Int, key: Data, crcCrypto: Bool = false) -> Data? {
        var partsToDecrypt: [Data] = []
        var iv: Data
        if counter > 0 {
            partsToDecrypt.append(data)
            guard let generatedIv = self.generateIv(counter: counter) else {
                return nil
            }
            iv = generatedIv
        } else {
            // forgive this crap, i want to completely remove myself from handling any crypto, and when crypto counter is 0, we don't increment the iv :sob: (NBCrypto crap)
            partsToDecrypt.append(contentsOf: stride(from: 0, to: data.count, by: 16).map { index in
                Data(data.bytes[index..<Swift.min(index + 16, data.count)])
            } as [Data])
            iv = self.firmwareData
        }

        var result = Data()
        for part in partsToDecrypt {
            let blockMode = CTR(iv: iv.bytes)
            guard let encrypted = try? AES(key: key.bytes, blockMode: blockMode, padding: .noPadding).encrypt(part.bytes) else {
                self.printDebug("Failed to do crypto - AES failed to init or do crypto (internal failure)")
                return nil
            }
            result.append(contentsOf: encrypted)
        }

        return result
    }

    private func crcCrypto(data: Data, counter: Int, key: Data) -> Data? {
        // not checking for data length >= 3 as this function is only called as a child of the encrypt function which already requires a certain min length among other things
        guard var iv = generateIv(counter: counter, crcData: data) else {
            return nil
        }
        
        let newIvBlockMode = CTR(iv: iv.bytes)
        guard let newIv = try? AES(key: key.bytes, blockMode: newIvBlockMode, padding: .zeroPadding).encrypt(data.bytes[..<3]) else {
            self.printDebug("Failed to do crcCrypto - AES failed to init or do crypto (internal failure)")
            return nil
        }

        var paddedData = Padding.zeroPadding.add(to: data[3...].bytes, blockSize: 16)
        paddedData.append(contentsOf: Data(count: 16))
        let nextRoundIvBlockMode = CFB(iv: newIv)
        guard let nextRoundIv = try? AES(key: key.bytes, blockMode: nextRoundIvBlockMode, padding: .noPadding).encrypt(paddedData).suffix(16) else {
            self.printDebug("Failed to do crcCrypto - failed to get next round iv (internal failure)")
            return nil
        }

        iv[0]  = 1
        iv[15] = 0
        let crcBlockMode = CTR(iv: iv.bytes)
        guard let crc = try? AES(key: key.bytes, blockMode: crcBlockMode).encrypt(nextRoundIv) else {
            self.printDebug("Failed to do crcCrypto - failed to encrypt final  (internal failure)")
            return nil
        }

        return Data(crc)
    }

   private func calcCrc(data: Data, counter: Int, key: Data) -> Data? {
        guard counter != 0 else {
            var crc = 0
            for value in data {
                crc += Int(value)
            }
            crc = ~crc
            var final = Data()
            final.append(Data(hex: "0000"))
            final.append(UInt8((crc & 0x00ff) >> 0))
            final.append(UInt8((crc & 0xff00) >> 8))
            return final
        }

        return crcCrypto(data: data, counter: counter, key: key)?.prefix(4)
   }
    
    private func printDebug(_ text: String) {
        guard self.debug else { return }
        print("[NinebotCrypto]", text)
    }

    private func calcKey(_ data1: Data, _ data2: Data) {
        var shaData = Data()

        var data1 = data1
        var data2 = data2

        if data1.count < 16 {
            data1.append(Data(count: 16 - data1.count))
        }

        if data2.count < 16 {
            data2.append(Data(count: 16 - data2.count))
        }

        shaData.append(data1.prefix(16))
        shaData.append(data2.prefix(16))

        self.key = Data(Insecure.SHA1.hash(data: shaData)).prefix(16)
    }
}
