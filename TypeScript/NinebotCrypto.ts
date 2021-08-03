import crypto from "crypto";

export class NinebotCrypto {
  public fwData = Buffer.from([
    0x97, 0xcf, 0xb8, 0x02, 0x84, 0x41, 0x43, 0xde, 0x56, 0x00, 0x2b, 0x3b,
    0x34, 0x78, 0x0a, 0x5d,
  ]);
  public randomBleData: Buffer = Buffer.alloc(16);
  public randomAppData: Buffer = Buffer.alloc(16);
  public shaKey: Buffer = Buffer.from([]);
  public name: string = "";
  public messageCount: number = 0;
  public serialNumber?: string;

  public setName(name: string): void {
    this.name = name;
    this.calcSha1Key(Buffer.from(this.name, "utf8"), this.fwData);
  }

  public encrypt(decryptedData: Buffer): Buffer | null {
    if (decryptedData[0] != 0x5a || decryptedData[1] != 0xa5) {
      console.warn("Invalid payload " + decryptedData.toString("hex"));
      return null;
    }

    let encrypted = Buffer.alloc(152);
    decryptedData.copy(encrypted, 0, 0, 3);

    let payloadLength = decryptedData.length - 3;
    let payload = Buffer.alloc(payloadLength);

    if (this.messageCount === 0) {
      const crc = this.calcCrcFirstMsg(payload);
      payload = this.cryptoFirst(payload);
      payload.copy(encrypted, 0, 3, payload.length);

      encrypted[payloadLength + 3] = 0;
      encrypted[payloadLength + 4] = 0;
      encrypted[payloadLength + 5] = crc[0];
      encrypted[payloadLength + 6] = crc[1];
      encrypted[payloadLength + 7] = 0;
      encrypted[payloadLength + 8] = 0;

      encrypted = encrypted.slice(0, payloadLength + 9);
      this.messageCount += 1;
    } else {
      this.messageCount += 1;
      const crc = this.calcCrcNextMsg(payload, this.messageCount);
      payload = this.cryptoNext(payload, this.messageCount);
      payload.copy(encrypted, 0, 3, payload.length);
      encrypted[payloadLength + 3] = crc[0];
      encrypted[payloadLength + 4] = crc[1];
      encrypted[payloadLength + 5] = crc[2];
      encrypted[payloadLength + 6] = crc[3];
      encrypted[payloadLength + 7] = (this.messageCount & 0x0000ff00) >> 8;
      encrypted[payloadLength + 8] = (this.messageCount & 0x000000ff) >> 0;
      encrypted = encrypted.slice(0, payloadLength + 9);

      if (
        decryptedData[0] == 0x5a &&
        decryptedData[1] == 0xa5 &&
        decryptedData[2] == 0x10 &&
        decryptedData[3] == 0x3e &&
        decryptedData[4] == 0x21 &&
        decryptedData[5] == 0x5c &&
        decryptedData[6] == 0x00
      ) {
        console.log("FILL THREE");

        decryptedData.copy(this.randomAppData, 7, 0, 16);
      }
    }
    return encrypted;
  }

  public decrypt(encryptedData: Buffer): Buffer | null {
    if (encryptedData[0] != 0x5a || encryptedData[1] != 0xa5) {
      console.warn("Invalid payload " + encryptedData.toString("hex"));
      return null;
    }

    let newMessageCount = this.messageCount;

    if (
      (newMessageCount & 0x0008000) > 0 &&
      encryptedData[encryptedData.length - 2] >> 7 == 0
    ) {
      newMessageCount += 0x0010000;
    }

    newMessageCount =
      (newMessageCount & 0xffff0000) +
      (encryptedData[encryptedData.length - 2] << 8) +
      encryptedData[encryptedData.length - 1];

    let payloadLength = encryptedData.length - 9;
    let payload = Buffer.concat([
      encryptedData.slice(0, 3),
      Buffer.alloc(payloadLength - 3),
    ]);
    let decryptedPayload = this.cryptoFirst(payload);
    let encryptedPayload = this.cryptoFirst(decryptedPayload);

    if (encryptedPayload != payload) {
      console.warn(
        "Decryption equality test failed during decryption of first message!",
        payload
      );
      return null;
    }

    const decrypted = Buffer.concat([encryptedData.slice(0, 3), payload]);

    if (
      decrypted[0] == 0x5a &&
      decrypted[1] == 0xa5 &&
      decrypted[2] == 0x1e &&
      decrypted[3] == 0x21 &&
      decrypted[4] == 0x3e &&
      decrypted[5] == 0x5b
    ) {
      this.serialNumber = decrypted
        .slice(decrypted.length - 15, decrypted.length - 1)
        .toString("ascii");
      console.log("Found SN:", this.serialNumber);

      decrypted.copy(this.randomBleData, 7, 0, 16);
      this.calcSha1Key(Buffer.from(this.name, "utf8"), this.randomBleData);
    } else if (newMessageCount > 0 && newMessageCount > this.messageCount) {
      let decryptedPayload = this.cryptoNext(payload, newMessageCount);
      let encryptedPayload = this.cryptoNext(decryptedPayload, newMessageCount);

      if (encryptedPayload != payload) {
        console.warn(
          "Decryption equality test failed during decryption of after first message!",
          payload
        );
        return null;
      }

      payload = decryptedPayload;
      payload.copy(decrypted, 0, 3, payload.length);

      if (
        decrypted[0] == 0x5a &&
        decrypted[1] == 0xa5 &&
        decrypted[2] == 0x00 &&
        decrypted[3] == 0x21 &&
        decrypted[4] == 0x3e &&
        decrypted[5] == 0x5c &&
        decrypted[6] == 0x01
      ) {
        console.log("FILL TWO");

        this.calcSha1Key(this.randomAppData.slice(0, 16), this.randomBleData);
      }

      this.messageCount = newMessageCount;
    }

    return decrypted;
  }

  private calcCrcFirstMsg(data: Buffer): Buffer {
    let crc = 0;

    for (let i = 0; i < data.length; ++i) {
      crc += data[i];
    }

    crc = ~crc;

    let ret = Buffer.alloc(2);
    ret[0] = crc & 0x00ff;
    ret[1] = (crc >> 8) & 0x0ff;

    return ret;
  }

  private calcCrcNextMsg(data: Buffer, msgIt: number): Buffer {
    let aesEncData = Buffer.alloc(16);

    let payloadLen = data.length - 3;
    let byteIdx = 3;

    let xorData1 = Buffer.alloc(16);
    let xorData2 = Buffer.alloc(16);

    aesEncData[0] = 89;
    aesEncData[1] = (msgIt & 0xff000000) >> 24;
    aesEncData[2] = (msgIt & 0x00ff0000) >> 16;
    aesEncData[3] = (msgIt & 0x0000ff00) >> 8;
    aesEncData[4] = (msgIt & 0x000000ff) >> 0;
    this.randomBleData.copy(aesEncData, 0, 5, 8);
    aesEncData[15] = payloadLen;

    let aesKey = this.aesEcbEncrypt(aesEncData, this.shaKey);
    aesKey.copy(xorData2, 0, 0, 16);

    data.copy(xorData1, 0, 3);

    let xorData = this.xor(xorData1, xorData2);

    aesKey = this.aesEcbEncrypt(xorData, this.shaKey);
    aesKey.copy(xorData2, 0, 0, 16);

    while (payloadLen > 0) {
      let tmpLen = payloadLen <= 16 ? payloadLen : 16;
      xorData1 = Buffer.alloc(16);

      data.copy(xorData1, byteIdx, 0, tmpLen);

      xorData = this.xor(xorData1, xorData2);

      aesKey = this.aesEcbEncrypt(xorData, this.shaKey);
      aesKey.copy(xorData2, 0, 0, 16);
      payloadLen -= tmpLen;
      byteIdx += tmpLen;
    }

    aesKey = this.aesEcbEncrypt(aesEncData, this.shaKey);
    aesKey.copy(xorData1, 0, 0, 4);
    xorData2.copy(xorData2, 0, 0, 4);

    aesEncData[0] = 1;
    aesEncData[15] = 0;

    return this.xor(xorData1, xorData2, 4);
  }

  public cryptoFirst(data: Buffer): Buffer {
    let result = Buffer.from("");

    let payloadLength = data.length;
    let byteIndex = 0;

    const xorData1 = Buffer.alloc(16);
    const xorData2 = Buffer.alloc(16);

    const aesKey = this.aesEcbEncrypt(this.fwData, this.shaKey);

    while (payloadLength > 0) {
      let tempLength = payloadLength <= 16 ? payloadLength : 16;

      data.copy(xorData1, byteIndex, 0, tempLength);
      aesKey.copy(xorData2, 0, 0, 16);

      const xor = this.xor(xorData1, xorData2);
      xor.copy(result, 0, byteIndex, tempLength);
      result = Buffer.concat([result, xor.slice(byteIndex, tempLength)]);

      payloadLength -= tempLength;
      byteIndex += tempLength;
    }

    return result;
  }

  public cryptoNext(data: Buffer, msgIt: number): Buffer {
    let result = Buffer.from("");

    let encryptedData = Buffer.alloc(16);
    encryptedData[0] = 1;
    encryptedData[1] = (msgIt & 0xff000000) >> 24;
    encryptedData[2] = (msgIt & 0x00ff0000) >> 16;
    encryptedData[3] = (msgIt & 0x0000ff00) >> 8;
    encryptedData[4] = (msgIt & 0x000000ff) >> 0;
    this.randomBleData.copy(encryptedData, 0, 5, 8);

    let payloadLength = data.length;
    let byteIndex = 0;

    const xorData1 = Buffer.alloc(16);
    const xorData2 = Buffer.alloc(16);

    const aesKey = this.aesEcbEncrypt(this.fwData, this.shaKey);

    while (payloadLength > 0) {
      encryptedData[15] += 1;
      let tempLength = payloadLength <= 16 ? payloadLength : 16;

      data.copy(xorData1, byteIndex, 0, tempLength);
      aesKey.copy(xorData2, 0, 0, 16);

      const xor = this.xor(xorData1, xorData2);
      xor.copy(result, 0, byteIndex, tempLength);
      result = Buffer.concat([result, xor.slice(byteIndex, tempLength)]);

      payloadLength -= tempLength;
      byteIndex += tempLength;
    }

    return result;
  }

  public xor(
    d1: Buffer,
    d2: Buffer,
    size: number = Math.min(d1.length, d2.length)
  ): Buffer {
    const data = Buffer.alloc(size);

    for (let i = 0; i < size; i++) data[i] = d1[i] ^ d2[i];

    return data;
  }

  public aesEcbEncrypt(data: Buffer, key: Buffer): Buffer {
    const cipher = crypto.createCipheriv("aes-128-ecb", key, "");
    cipher.setAutoPadding(false);
    return Buffer.concat([cipher.update(data), cipher.final()]);
  }

  private calcSha1Key(d1: Buffer, d2: Buffer): Buffer {
    let key = Buffer.alloc(32);

    d1.copy(key);
    d2.copy(key, 16);

    key = crypto
      .createHash("sha1")
      .update(key.slice(0, 32))
      .digest()
      .slice(0, 16);

    this.shaKey = key;

    console.log("shaKey", this.shaKey);

    return key;
  }
}
