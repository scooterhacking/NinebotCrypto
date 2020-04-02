using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using System.Threading.Tasks;
using Windows.Security.Cryptography.Core;

namespace es2_Flasher
{
    class NinebotCrypto
    {
        private static readonly byte[] _fw_data = { 0x97, 0xCF, 0xB8, 0x02, 0x84, 0x41, 0x43, 0xDE, 0x56, 0x00, 0x2B, 0x3B, 0x34, 0x78, 0x0A, 0x5D };
        private byte[] _random_ble_data = new byte[16];
        private byte[] _random_app_data = new byte[16];
        private byte[] _sha1_key = new byte[16];

        private UInt32 _msg_it = 0;

        private string _name;

        public NinebotCrypto(string Name)
        {
            _name = Name;
            Array.Clear(_random_ble_data, 0, _random_ble_data.Length);
            CalcSha1Key(Encoding.ASCII.GetBytes(_name), _fw_data);
        }

        public byte[] Decrypt(byte[] Data)
        {
            byte[] decrypted = new byte[Data.Length - 6];

            Buffer.BlockCopy(Data, 0, decrypted, 0, 3);

            UInt32 new_msg_it = _msg_it;
            if ((new_msg_it & 0x0008000) > 0 && (Data[Data.Length - 2] >> 7) == 0)
            {
                new_msg_it += 0x0010000;
            }

            new_msg_it = (new_msg_it & 0xFFFF0000) +
                         (UInt32)(Data[Data.Length - 2] << 8) +
                         Data[Data.Length - 1];

            int payload_len = Data.Length - 9;
            byte[] payload = new byte[payload_len];
            Buffer.BlockCopy(Data, 3, payload, 0, payload_len);

            if (new_msg_it == 0)
            {
                var payload_d = CryptoFirst(payload);
                var payload_e = CryptoFirst(payload_d);
                var eq = payload_e.SequenceEqual(payload);
                if (eq == false)
                {
                    System.Diagnostics.Debug.WriteLine(String.Format("First Not eq \n\t{0}\n\t{1}\n\t{2}",
                        Windows.Security.Cryptography.CryptographicBuffer.EncodeToHexString(payload.AsBuffer()),
                        Windows.Security.Cryptography.CryptographicBuffer.EncodeToHexString(payload_d.AsBuffer()),
                        Windows.Security.Cryptography.CryptographicBuffer.EncodeToHexString(payload_e.AsBuffer())));

                }

                payload = CryptoFirst(payload);

                Buffer.BlockCopy(payload, 0, decrypted, 3, payload.Length);

                if (decrypted[0] == 0x5A &&
                    decrypted[1] == 0xA5 &&
                    decrypted[2] == 0x1E &&
                    decrypted[3] == 0x21 &&
                    decrypted[4] == 0x3E &&
                    decrypted[5] == 0x5B )
                {
                    Buffer.BlockCopy(decrypted, 7, _random_ble_data, 0, 16);
                    CalcSha1Key(Encoding.ASCII.GetBytes(_name), _random_ble_data);
                }
            }
            else if (new_msg_it > 0 && new_msg_it > _msg_it)
            {
                var payload_d = CryptoNext(payload, new_msg_it);
                var payload_e = CryptoNext(payload_d, new_msg_it);
                var eq = payload_e.SequenceEqual(payload);
                if (eq == false)
                {
                    System.Diagnostics.Debug.WriteLine(String.Format("Next Not eq \n\t{0}\n\t{1}\n\t{2}",
                        Windows.Security.Cryptography.CryptographicBuffer.EncodeToHexString(payload.AsBuffer()),
                        Windows.Security.Cryptography.CryptographicBuffer.EncodeToHexString(payload_d.AsBuffer()),
                        Windows.Security.Cryptography.CryptographicBuffer.EncodeToHexString(payload_e.AsBuffer())));
                }

                payload = CryptoNext(payload, new_msg_it);

                Buffer.BlockCopy(payload, 0, decrypted, 3, payload.Length);

                if (decrypted[0] == 0x5A &&
                    decrypted[1] == 0xA5 &&
                    decrypted[2] == 0x00 &&
                    decrypted[3] == 0x21 &&
                    decrypted[4] == 0x3E &&
                    decrypted[5] == 0x5C &&
                    decrypted[6] == 0x01)
                {
                    CalcSha1Key(_random_app_data, _random_ble_data);
                }

                _msg_it = new_msg_it;
            }

            System.Diagnostics.Debug.WriteLine(String.Format("e string e = \"{0}\";", Windows.Security.Cryptography.CryptographicBuffer.EncodeToHexString(Data.AsBuffer())));
            System.Diagnostics.Debug.WriteLine(String.Format("e string d = \"{0}\";", Windows.Security.Cryptography.CryptographicBuffer.EncodeToHexString(decrypted.AsBuffer())));
            return decrypted;
        }

        public byte[] Encrypt(byte[] Data)
        {
            byte[] encrypted = new byte[152];

            Buffer.BlockCopy(Data, 0, encrypted, 0, 3);

            int payload_len = Data.Length - 3;

            byte[] payload = new byte[payload_len];
            Buffer.BlockCopy(Data, 3, payload, 0, payload_len);

            if (_msg_it == 0)
            {
                byte[] crc = CalcCrcFirstMsg(payload);
                payload = CryptoFirst(payload);

                Buffer.BlockCopy(payload, 0, encrypted, 3, payload.Length);

                encrypted[payload_len + 3] = 0;
                encrypted[payload_len + 4] = 0;
                encrypted[payload_len + 5] = crc[0];
                encrypted[payload_len + 6] = crc[1];
                encrypted[payload_len + 7] = 0;
                encrypted[payload_len + 8] = 0;
                encrypted = encrypted.Take(payload_len + 9).ToArray();
                _msg_it++;
            }
            else
            {
                _msg_it++;

                byte[] crc = CalcCrcNextMsg(Data, _msg_it);
                payload = CryptoNext(payload, _msg_it);

                Buffer.BlockCopy(payload, 0, encrypted, 3, payload.Length);

                encrypted[payload_len + 3] = crc[0];
                encrypted[payload_len + 4] = crc[1];
                encrypted[payload_len + 5] = crc[2];
                encrypted[payload_len + 6] = crc[3];
                encrypted[payload_len + 7] = (byte)((_msg_it & 0x0000FF00) >> 8);
                encrypted[payload_len + 8] = (byte)((_msg_it & 0x000000FF) >> 0);
                encrypted = encrypted.Take(payload_len + 9).ToArray();

                if (Data[0] == 0x5A &&
                    Data[1] == 0xA5 &&
                    Data[2] == 0x10 &&
                    Data[3] == 0x3E &&
                    Data[4] == 0x21 &&
                    Data[5] == 0x5C &&
                    Data[6] == 0x00)
                {
                    Buffer.BlockCopy(Data, 7, _random_app_data, 0, 16);
                }
            }

            System.Diagnostics.Debug.WriteLine(String.Format("d string d = \"{0}\";", Windows.Security.Cryptography.CryptographicBuffer.EncodeToHexString(Data.AsBuffer())));
            System.Diagnostics.Debug.WriteLine(String.Format("d string e = \"{0}\";", Windows.Security.Cryptography.CryptographicBuffer.EncodeToHexString(encrypted.AsBuffer())));
            return encrypted;
        }

        private byte[] CryptoFirst(byte[] Data)
        {
            byte[] result = new byte[Data.Length];

            int payload_len = Data.Length;
            int byte_idx = 0;

            byte[] xor_data_1 = new byte[16];
            byte[] xor_data_2 = new byte[16];

            while (payload_len > 0)
            {
                int tmp_len = (payload_len <= 16) ? payload_len : 16;

                Array.Clear(xor_data_1, 0, xor_data_1.Length);
                Buffer.BlockCopy(Data, byte_idx, xor_data_1, 0, tmp_len);

                byte[] aes_key = AesEcbEncrypt(_fw_data, _sha1_key);
                Buffer.BlockCopy(aes_key, 0, xor_data_2, 0, 16);
                byte[] xor_data = XOR(xor_data_1, xor_data_2, 16);

                Buffer.BlockCopy(xor_data, 0, result, byte_idx, tmp_len);
                payload_len -= tmp_len;
                byte_idx += tmp_len;
            }

            return result;
        }

        private byte[] CryptoNext(byte[] Data, UInt32 MsgIt)
        {
            byte[] result = new byte[Data.Length];

            byte[] aes_enc_data = new byte[16];
            Array.Clear(aes_enc_data, 0, 16);
            aes_enc_data[0] = 1;
            aes_enc_data[1] = (byte)((MsgIt & 0xFF000000) >> 24);
            aes_enc_data[2] = (byte)((MsgIt & 0x00FF0000) >> 16);
            aes_enc_data[3] = (byte)((MsgIt & 0x0000FF00) >> 8);
            aes_enc_data[4] = (byte)((MsgIt & 0x000000FF) >> 0);
            Buffer.BlockCopy(_random_ble_data, 0, aes_enc_data, 5, 8);
            aes_enc_data[15] = 0;

            int payload_len = Data.Length;
            int byte_idx = 0;

            byte[] xor_data_1 = new byte[16];
            byte[] xor_data_2 = new byte[16];

            while (payload_len > 0)
            {
                ++aes_enc_data[15];

                int tmp_len = (payload_len <= 16) ? payload_len : 16;

                Array.Clear(xor_data_1, 0, 16);
                Buffer.BlockCopy(Data, byte_idx, xor_data_1, 0, tmp_len);

                byte[] aes_key = AesEcbEncrypt(aes_enc_data, _sha1_key);
                Buffer.BlockCopy(aes_key, 0, xor_data_2, 0, 16);
                byte[] xor_data = XOR(xor_data_1, xor_data_2, 16);

                Buffer.BlockCopy(xor_data, 0, result, byte_idx, tmp_len);
                payload_len -= tmp_len;
                byte_idx += tmp_len;
            }

            return result;
        }

        private byte[] CalcCrcFirstMsg(byte[] data)
        {
            UInt16 crc = 0;
            for (int i = 0; i < data.Length; ++i)
            {
                crc += data[i];
            }

            crc = (UInt16)(~crc);

            byte[] ret = new byte[2];
            ret[0] = (byte)(crc & 0x00ff);
            ret[1] = (byte)((crc >> 8) & 0x0ff);

            return ret;
        }

        private byte[] CalcCrcNextMsg(byte[] Data, UInt32 MsgIt)
        {
            byte[] aes_enc_data = new byte[16];
            Array.Clear(aes_enc_data, 0, 16);

            int payload_len = Data.Length - 3;
            int byte_idx = 3;
            byte[] xor_data_1 = new byte[16];
            byte[] xor_data_2 = new byte[16];
            byte[] xor_data = null;
            byte[] aes_key = null;

            aes_enc_data[0] = 89;
            aes_enc_data[1] = (byte)((MsgIt & 0xFF000000) >> 24);
            aes_enc_data[2] = (byte)((MsgIt & 0x00FF0000) >> 16);
            aes_enc_data[3] = (byte)((MsgIt & 0x0000FF00) >> 8);
            aes_enc_data[4] = (byte)((MsgIt & 0x000000FF) >> 0);
            Buffer.BlockCopy(_random_ble_data, 0, aes_enc_data, 5, 8);
            aes_enc_data[15] = (byte)payload_len;

            aes_key = AesEcbEncrypt(aes_enc_data, _sha1_key);
            Buffer.BlockCopy(aes_key, 0, xor_data_2, 0, 16);

            Array.Clear(xor_data_1, 0, 16);
            Buffer.BlockCopy(Data, 0, xor_data_1, 0, 3);

            xor_data = XOR(xor_data_1, xor_data_2, 16);
            aes_key = AesEcbEncrypt(xor_data, _sha1_key);
            Buffer.BlockCopy(aes_key, 0, xor_data_2, 0, 16);

            while (payload_len > 0)
            {
                int tmp_len = (payload_len <= 16) ? payload_len : 16;

                Array.Clear(xor_data_1, 0, 16);
                Buffer.BlockCopy(Data, byte_idx, xor_data_1, 0, tmp_len);

                xor_data = XOR(xor_data_1, xor_data_2, 16);

                aes_key = AesEcbEncrypt(xor_data, _sha1_key);
                Buffer.BlockCopy(aes_key, 0, xor_data_2, 0, 16);
                payload_len -= tmp_len;
                byte_idx += tmp_len;
            }

            aes_enc_data[0] = 1;
            aes_enc_data[15] = 0;

            aes_key = AesEcbEncrypt(aes_enc_data, _sha1_key);
            Buffer.BlockCopy(aes_key, 0, xor_data_1, 0, 4);
            Buffer.BlockCopy(xor_data_2, 0, xor_data_2, 0, 4);

            return XOR(xor_data_1, xor_data_2, 4);
        }

        private void CalcSha1Key(byte[] sha1_data_1, byte[] sha1_data_2)
        {
            byte[] sha_data = new byte[32];
            sha1_data_1.CopyTo(sha_data, 0);
            sha1_data_2.CopyTo(sha_data, 16);

            byte[] sha_hash = Sha1(sha_data);
            Buffer.BlockCopy(sha_hash, 0, _sha1_key, 0, 16);
        }

        private byte[] AesEcbEncrypt(byte[] data, byte[] key)
        {
            SymmetricKeyAlgorithmProvider aes = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesEcb);
            var symetricKey = aes.CreateSymmetricKey(key.AsBuffer());
            var buffEncrypted = CryptographicEngine.Encrypt(symetricKey, data.AsBuffer(), null);

            return buffEncrypted.ToArray();
        }

        private byte[] Sha1(byte[] data)
        {
            HashAlgorithmProvider sha1 = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Sha1);
            var buffSha1 = sha1.HashData(data.AsBuffer());

            return buffSha1.ToArray();
        }

        private byte[] XOR(byte[] data_1, byte[] data_2, int size)
        {
            byte[] data = new byte[size];
            for (int i = 0; i < size; i++)
                data[i] = (byte)(data_1[i] ^ data_2[i]);
            return data;
        }
    }
}
