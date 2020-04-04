package adriandp.core.util

import android.util.Log
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.xor

@ExperimentalUnsignedTypes
class ProtocolNinebot(private val _name: String) {

    private val dataBasic = byteArrayOf(0x97.toByte(), 0xCF.toByte(), 0xB8.toByte(), 0x02, 0x84.toByte(), 0x41, 0x43, 0xDE.toByte(), 0x56, 0x00, 0x2B, 0x3B, 0x34, 0x78, 0x0A, 0x5D)
    private val randomBleData = ByteArray(16)
    private val randomAppData = ByteArray(16)
    private var initialFirstPart: ByteArray? = null
    private var initialSecondPart: ByteArray? = null

    private var initialThirdPart: ByteArray? = null
    private var finalRequestInitial: ByteArray? = null
    private var finalRequestInitialHex: ByteArray? = null
    var randomKey: String? = null
    val shaKey = ByteArray(16)
    var serialNumber: String = ""


    private var msgIt: UInt =  0u
    var firstKey = true
    var getInitialProcess = false
    var isComplete = false

    init {
        calcSha1Key(_name.toByteArray(), dataBasic)
    }

    private fun ByteArray.toHexString() = joinToString("") { "%02x".format(it) }

    fun decrypt(Data: ByteArray, force: Boolean = false): ByteArray {
        
        val decrypted = ByteArray(Data.size - 6)
        System.arraycopy(Data, 0, decrypted, 0, 3)
        var negative = false
        var newMsgIt: UInt = msgIt
        
        newMsgIt = (newMsgIt and 4294901760u) + ((((Data[Data.size - 2].toLong() and 255) shl 8).toUInt()) + (Data[Data.size - 1].toInt() and 0xff).toUInt())

        val payloadLen: Int = Data.size - 9
        var payload: ByteArray? = ByteArray(payloadLen)
        System.arraycopy(Data, 3, payload, 0, payloadLen)
        if (newMsgIt == 0u) {

            val payloadD = cryptoFirst(payload!!)
            val payloadE = cryptoFirst(payloadD)

            val eq = payloadE.contentEquals(payload)
            if (!eq) {
                println("\\${payload.toHexString()}\n" +
                        "\\${payloadD.toHexString()}\n" +
                        "\\${payloadE.toHexString()}\")")
           }
            payload = cryptoFirst(payload)
            System.arraycopy(payload, 0, decrypted, 3, payload.size)
            if (decrypted[0] == 0x5A.toByte() &&
                    decrypted[1] == 0xA5.toByte() &&
                    decrypted[2] == 0x1E.toByte() &&
                    decrypted[3] == 0x21.toByte() &&
                    decrypted[4] == 0x3E.toByte() &&
                    decrypted[5] == 0x5B.toByte()) {
                System.arraycopy(decrypted, 7, randomBleData, 0, 16)
                calcSha1Key(_name.toByteArray(), randomBleData)
            }
        } else {
            val payloadD = cryptoNext(payload!!, newMsgIt)
            val payloadE = cryptoNext(payloadD, newMsgIt)
            val eq = payloadE.contentEquals(payload)
            if (!eq) {
                println("First Not eq \n" +
                        "\\${payload.toHexString()}\n" +
                        "\\${payloadD.toHexString()}\n" +
                        "\\${payloadE.toHexString()}\")")
            }
            payload = cryptoNext(payload, newMsgIt)
            System.arraycopy(payload, 0, decrypted, 3, payload.size)
            if (decrypted[0] == 0x5A.toByte() &&
                    decrypted[1] == 0xA5.toByte() &&
                    decrypted[2] == 0x00.toByte() &&
                    decrypted[3] == 0x21.toByte() &&
                    decrypted[4] == 0x3E.toByte() &&
                    decrypted[5] == 0x5C.toByte() &&
                    decrypted[6] == 0x01.toByte()) {
                calcSha1Key(randomAppData, randomBleData)
            }

            if (negative) {
                Log.d("ToothSErvice", "intial contador decript -> $msgIt")
                msgIt++
                Log.d("ToothSErvice", "contador decript +1 -> $msgIt")
            } else {
                Log.d("ToothSErvice", "intial contador decript = -> $msgIt")
                if (msgIt > newMsgIt) {
                    msgIt = newMsgIt
                }
                
                Log.d("ToothSErvice", "contador decript = -> $msgIt")
            }

        }
        
        return decrypted
    }

    fun encrypt(Data: ByteArray): ByteArray {

        Log.d("ToothSErvice", "Init contador encript -> ${msgIt}")
        var encrypted = ByteArray(152)
        System.arraycopy(Data, 0, encrypted, 0, 3)
        val payloadLen: Int = Data.size - 3
        var payload = ByteArray(payloadLen)
        System.arraycopy(Data, 3, payload, 0, payloadLen)
        if (msgIt == 0u) {
            val crc: ByteArray = calcCrcFirstMsg(payload)
            payload = cryptoFirst(payload)
            System.arraycopy(payload, 0, encrypted, 3, payload.size)
            encrypted[payloadLen + 3] = 0
            encrypted[payloadLen + 4] = 0
            encrypted[payloadLen + 5] = crc[0]
            encrypted[payloadLen + 6] = crc[1]
            encrypted[payloadLen + 7] = 0
            encrypted[payloadLen + 8] = 0
            encrypted = encrypted.take(payloadLen + 9).toByteArray()
            msgIt++
        } else {
            msgIt++
            val crc: ByteArray = calcCrcNextMsg(Data, msgIt)
            payload = cryptoNext(payload, msgIt)
            System.arraycopy(payload, 0, encrypted, 3, payload.size)
            encrypted[payloadLen + 3] = crc[0]
            encrypted[payloadLen + 4] = crc[1]
            encrypted[payloadLen + 5] = crc[2]
            encrypted[payloadLen + 6] = crc[3]
            encrypted[payloadLen + 7] = ((msgIt and 65280u) shr 8).toByte()
            encrypted[payloadLen + 8] = ((msgIt and 255u) shr 0).toByte()
            encrypted = encrypted.take(payloadLen + 9).toByteArray()
            if (Data[0] == 0x5A.toByte() &&
                    Data[1] == 0xA5.toByte() &&
                    Data[2] == 0x10.toByte() &&
                    Data[3] == 0x3E.toByte() &&
                    Data[4] == 0x21.toByte() &&
                    Data[5] == 0x5C.toByte() &&
                    Data[6] == 0x00.toByte()) {
                System.arraycopy(Data, 7, randomAppData, 0, 16)
            }
        }



        Log.d("ToothSErvice", "contador encript -> ${msgIt}")
        Log.d("ToothSErvice", "Encripted -> ${encrypted.toHexString()}")

       
        return encrypted
    }

    private fun calcCrcFirstMsg(data: ByteArray): ByteArray {
        var crc: Long = 0
        for (element in data) {
            crc += element
        }
        crc = crc.inv()
        val ret = ByteArray(2)
        ret[0] = (crc and 0x00ff).toByte()
        ret[1] = ((crc shr 8) and 0x0ff).toByte()
        return ret
    }

    private fun calcCrcNextMsg(Data: ByteArray, MsgIt: UInt): ByteArray {
        val aesEncData = ByteArray(16)
        //Array.Clear(aes_enc_data, 0, 16)
        var payloadLen: Int = Data.size - 3
        var byteIdx = 3
        var xorData1: ByteArray
        val xorData2 = ByteArray(16)
        var xorData: ByteArray?
        var aesKey: ByteArray?

        aesEncData[0] = 89
        aesEncData[1] = ((MsgIt and 4278190080u) shr 24).toByte()
        aesEncData[2] = ((MsgIt and 16711680u) shr 16).toByte()
        aesEncData[3] = ((MsgIt and 65280u) shr 8).toByte()
        aesEncData[4] = ((MsgIt and 255u) shr 0).toByte()
        System.arraycopy(randomBleData, 0, aesEncData, 5, 8)
        aesEncData[15] = payloadLen.toByte()

        aesKey = aesEcbEncrypt(aesEncData, shaKey)
        System.arraycopy(aesKey, 0, xorData2, 0, 16)

        xorData1 = ByteArray(16)
        System.arraycopy(Data, 0, xorData1, 0, 3)

        xorData = createXor(xorData1, xorData2)
        aesKey = aesEcbEncrypt(xorData, shaKey)
        System.arraycopy(aesKey, 0, xorData2, 0, 16)

        while (payloadLen > 0) {
            val tmpLen = if (payloadLen <= 16) payloadLen else 16

            xorData1 = ByteArray(16)
            System.arraycopy(Data, byteIdx, xorData1, 0, tmpLen)

            xorData = createXor(xorData1, xorData2)

            aesKey = aesEcbEncrypt(xorData, shaKey)
            System.arraycopy(aesKey, 0, xorData2, 0, 16)
            payloadLen -= tmpLen
            byteIdx += tmpLen
        }

        aesEncData[0] = 1
        aesEncData[15] = 0

        aesKey = aesEcbEncrypt(aesEncData, shaKey)
        System.arraycopy(aesKey, 0, xorData1, 0, 4)
        System.arraycopy(xorData2, 0, xorData2, 0, 4)

        return createXor(xorData1, xorData2)
    }

    private fun calcSha1Key(sha1_data_1: ByteArray, sha1_data_2: ByteArray) {
        val shaData = ByteArray(32)
        sha1_data_1.copyInto(shaData, 0)
        sha1_data_2.copyInto(shaData, 16)

        val shaHash: ByteArray = sha1(shaData)
        System.arraycopy(shaHash, 0, shaKey, 0, 16)

        //println(shaKey.toHexString())
    }

    private fun sha1(textBytes: ByteArray): ByteArray {
        val md: MessageDigest = MessageDigest.getInstance("SHA-1")
        md.update(textBytes, 0, textBytes.size)
        return md.digest()
    }

    private fun cryptoNext(Data: ByteArray, MsgIt: UInt): ByteArray {
        val result = ByteArray(Data.size)
        val aesEncData = ByteArray(16) { 0 }
        //Array.Clear(aes_enc_data, 0, 16)
        aesEncData[0] = 1
        aesEncData[1] = ((MsgIt and 4278190080u) shr 24).toByte()
        aesEncData[2] = ((MsgIt and 16711680u) shr 16).toByte()
        aesEncData[3] = ((MsgIt and 65280u) shr 8).toByte()
        aesEncData[4] = ((MsgIt and 255u) shr 0).toByte()
        System.arraycopy(randomBleData, 0, aesEncData, 5, 8)
        aesEncData[15] = 0

        var payloadLen: Int = Data.size
        var byteidx = 0
        val xordata1 = ByteArray(16)
        val xordata2 = ByteArray(16)


        while (payloadLen > 0) {

            ++aesEncData[15]

            val tmpLen = if (payloadLen <= 16) payloadLen else 16

            System.arraycopy(Data, byteidx, xordata1, 0, tmpLen)

            val aesKey: ByteArray = aesEcbEncrypt(aesEncData, shaKey)
            System.arraycopy(aesKey, 0, xordata2, 0, 16)
            val xorData: ByteArray = createXor(xordata1, xordata2)

            System.arraycopy(xorData, 0, result, byteidx, tmpLen)
            payloadLen -= tmpLen
            byteidx += tmpLen
        }
        return result
    }

    private fun cryptoFirst(Data: ByteArray): ByteArray {
        val result = ByteArray(Data.size)
        var payloadLen: Int = Data.size
        var byteidx = 0
        val xordata1 = ByteArray(16)
        val xordata2 = ByteArray(16)

        while (payloadLen > 0) {
            val tmpLen = if (payloadLen <= 16) payloadLen else 16
            System.arraycopy(Data, byteidx, xordata1, 0, tmpLen)

            val aesKey: ByteArray = aesEcbEncrypt(dataBasic, shaKey)
            System.arraycopy(aesKey, 0, xordata2, 0, 16)
            val xorData: ByteArray = createXor(xordata1, xordata2)

            System.arraycopy(xorData, 0, result, byteidx, tmpLen)
            payloadLen -= tmpLen
            byteidx += tmpLen
        }
        return result
    }

    private fun aesEcbEncrypt(fileData: ByteArray, data: ByteArray): ByteArray {
        val secretKey = SecretKeySpec(data, "AES")
        val cipher = Cipher.getInstance("AES")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        return cipher.doFinal(fileData)
    }

    private fun createXor(xorData1: ByteArray, xorData2: ByteArray): ByteArray {
        val result = xorData1.clone()
        xorData1.forEachIndexed { index, byte ->
            result[index] = xorData2[index] xor byte
        }

        return result
    }

    fun putInitialRequest(bytes: ByteArray/*, fWriter: FileWriter*/): Boolean {
        when {
            initialFirstPart == null -> {
                initialFirstPart = bytes
                //     fWriter.append("initialFirstPart true -> ${initialFirstPart!!.toHexString()} ").flush()
                return false
            }
            initialSecondPart == null -> {
                initialSecondPart = bytes
                //  fWriter.append("initialSecondPart second ${initialSecondPart!!.toHexString()} ").flush()
                return false
            }
            initialThirdPart == null -> {
                initialThirdPart = bytes
                // fWriter.append("initialThirdPart third ${initialThirdPart!!.toHexString()}\n ").flush()
                // fWriter.append("all request ->${initialFirstPart!!.toHexString()}${initialSecondPart!!.toHexString()}${initialThirdPart!!.toHexString()}\n").flush()

                val decript = decrypt(initialFirstPart!! + initialSecondPart!! + initialThirdPart!!)
                Log.d("ToothSErvice", "finalRequestInitial decript!-> ${decript.toHexString()} \n")
                finalRequestInitial = decript
                finalRequestInitialHex = decript
                val hex = decript.toHexString()
                serialNumber = hex.substring(hex.length - 28, hex.length).format(1234)

                Log.d("ToothSErvice", "serialNumber -> $serialNumber \n")

                val SOURCES = "abcde1234567890"
                randomKey = (1..32).map { SOURCES.random() }.joinToString("")

                Log.d("ToothSErvice", "randomKey = 5aa5103e215c00+${randomKey!!} \n")
                getInitialProcess = true

                return true
            }
        }
        throw  IllegalStateException("fail!! ")
    }
}
