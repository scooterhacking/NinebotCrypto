#include "NinebotCrypto.h"
#include <algorithm>
#include "aes.hpp"  // from Tiny-AES-c
#include <cstring>
#include "sha1.h" // from https://github.com/clibs/sha1

NinebotCrypto::VarArray NinebotCrypto::CryptoFirst(const VarArray &Data) {
	std::vector<uint8_t> result;
	result.resize(Data.size());

	size_t payload_len = Data.size();
	size_t byte_idx = 0;

	Array16 xor_data_1;
	Array16 xor_data_2;

	while (payload_len > 0) {
		int tmp_len = (payload_len <= 16) ? payload_len : 16;

		xor_data_1.fill(0);
		BlockCopy(Data, byte_idx, xor_data_1, 0, tmp_len);

		Array16 aes_key = AesEcbEncrypt(_fw_data, _sha1_key);
		BlockCopy(aes_key, 0, xor_data_2, 0, 16);
		Array16 xor_data = XOR16(xor_data_1, xor_data_2);

		BlockCopy(xor_data, 0, result, byte_idx, tmp_len);
		payload_len -= tmp_len;
		byte_idx += tmp_len;
	}

	return result;
}

NinebotCrypto::VarArray NinebotCrypto::CryptoNext(const VarArray &Data, const uint32_t MsgIt) {
	std::vector<uint8_t> result;
	result.resize(Data.size());

	Array16 aes_enc_data;
	aes_enc_data.fill(0);

	aes_enc_data[0] = 1;
	aes_enc_data[1] = (uint8_t)((MsgIt & 0xFF000000) >> 24);
	aes_enc_data[2] = (uint8_t)((MsgIt & 0x00FF0000) >> 16);
	aes_enc_data[3] = (uint8_t)((MsgIt & 0x0000FF00) >> 8);
	aes_enc_data[4] = (uint8_t)((MsgIt & 0x000000FF) >> 0);
	BlockCopy(_random_ble_data, 0, aes_enc_data, 5, 8);
	aes_enc_data[15] = 0;

	size_t payload_len = Data.size();
	size_t byte_idx = 0;

	Array16 xor_data_1;
	Array16 xor_data_2;

	while (payload_len > 0) {
		++aes_enc_data[15];

		int tmp_len = (payload_len <= 16) ? payload_len : 16;

		xor_data_1.fill(0);
		BlockCopy(Data, byte_idx, xor_data_1, 0, tmp_len);

		Array16 aes_key = AesEcbEncrypt(aes_enc_data, _sha1_key);
		BlockCopy(aes_key, 0, xor_data_2, 0, 16);
		Array16 xor_data = XOR16(xor_data_1, xor_data_2);

		BlockCopy(xor_data, 0, result, byte_idx, tmp_len);
		payload_len -= tmp_len;
		byte_idx += tmp_len;
	}

	return result;
}

std::array<uint8_t, 2> NinebotCrypto::CalcCrcFirstMsg(const VarArray &Data) {
	uint16_t crc = 0;
	for (auto &v : Data)
		crc += v;

	crc = (uint16_t)(~crc);
	return { (uint8_t)(crc & 0x00ff), (uint8_t)((crc >> 8) & 0x0ff) };
}

std::array<uint8_t, 4> NinebotCrypto::CalcCrcNextMsg(const VarArray &Data, const uint32_t MsgIt) {
	std::array<uint8_t, 16> aes_enc_data;
	aes_enc_data.fill(0);

	int payload_len = Data.size() - 3;
	int byte_idx = 3;
	Array16 xor_data_1, xor_data_2;
	Array16 xor_data, aes_key;

	aes_enc_data[0] = 89;
	aes_enc_data[1] = (uint8_t)((MsgIt & 0xFF000000) >> 24);
	aes_enc_data[2] = (uint8_t)((MsgIt & 0x00FF0000) >> 16);
	aes_enc_data[3] = (uint8_t)((MsgIt & 0x0000FF00) >> 8);
	aes_enc_data[4] = (uint8_t)((MsgIt & 0x000000FF) >> 0);
	BlockCopy(_random_ble_data, 0, aes_enc_data, 5, 8);
	aes_enc_data[15] = (uint8_t)payload_len;

	aes_key = AesEcbEncrypt(aes_enc_data, _sha1_key);
	BlockCopy(aes_key, 0, xor_data_2, 0, 16);

	xor_data_1.fill(0);
	BlockCopy(Data, 0, xor_data_1, 0, 3);

	xor_data = XOR16(xor_data_1, xor_data_2);
	aes_key = AesEcbEncrypt(xor_data, _sha1_key);
	BlockCopy(aes_key, 0, xor_data_2, 0, 16);

	while (payload_len > 0) {
		size_t tmp_len = (payload_len <= 16) ? payload_len : 16;

		xor_data_1.fill(0);
		BlockCopy(Data, byte_idx, xor_data_1, 0, tmp_len);

		xor_data = XOR16(xor_data_1, xor_data_2);

		aes_key = AesEcbEncrypt(xor_data, _sha1_key);
		BlockCopy(aes_key, 0, xor_data_2, 0, 16);

		payload_len -= tmp_len;
		byte_idx += tmp_len;
	}

	aes_enc_data[0] = 1;
	aes_enc_data[15] = 0;

	aes_key = AesEcbEncrypt(aes_enc_data, _sha1_key);
	BlockCopy(aes_key   , 0, xor_data_1, 0, 16);
	BlockCopy(xor_data_2, 0, xor_data_2, 0, 16);
	xor_data = XOR16(xor_data_1, xor_data_2);
	return { xor_data[0], xor_data[1], xor_data[2], xor_data[3] };
}

void NinebotCrypto::CalcSha1Key(const Array16 &Data1, const Array16 &Data2) {
	std::array<uint8_t, 32> Data;
	BlockCopy(Data1,  0, Data, 0, 16);
	BlockCopy(Data2,  0, Data, 16, 16);

	std::array<uint8_t, 20> Hash = Sha1(Data);
	BlockCopy(Hash, 0, _sha1_key, 0, 16);
}

NinebotCrypto::Array16 NinebotCrypto::AesEcbEncrypt(const Array16 &Data, const Array16 &key) {
    Array16 output;
    memcpy(output.data(), Data.data(), 16);
    
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key.data());
    
    AES_ECB_encrypt(&ctx, output.data());
    
    return output;
}



std::array<uint8_t, 20> NinebotCrypto::Sha1(const std::array<uint8_t, 32>& Data) {
    std::array<uint8_t, 20> hash;
    SHA1(reinterpret_cast<char*>(hash.data()), reinterpret_cast<const char*>(Data.data()), Data.size());
    return hash;
}

NinebotCrypto::Array16 NinebotCrypto::XOR16(const Array16 &Data1, const Array16 &Data2) {
    Array16 Data;
    for (size_t i = 0; i < 16; ++i)
        Data[i] = Data1[i] ^ Data2[i];
    return Data;
}

NinebotCrypto::NinebotCrypto(std::string Name) {
    _name.fill(0);
    _random_ble_data.fill(0);
    std::copy(Name.begin(), Name.end(), _name.begin());
    CalcSha1Key(_name, _fw_data);
}

NinebotCrypto::VarArray NinebotCrypto::Decrypt(const VarArray &Data) {
	std::vector<uint8_t> decrypted;
	decrypted.resize(Data.size() - 6);

	BlockCopy(Data, 0, decrypted, 0, 3);

	uint32_t new_msg_it = _msg_it;
	if ((new_msg_it & 0x0008000) > 0 && (Data[Data.size() - 2] >> 7) == 0) {
		new_msg_it += 0x0010000;
	}

	new_msg_it = (new_msg_it & 0xFFFF0000) +
	             (uint32_t)(Data[Data.size() - 2] << 8) +
	             Data[Data.size() - 1];

	size_t payload_len = Data.size() - 9;
	std::vector<uint8_t> payload;
	payload.resize(payload_len);
	BlockCopy(Data, 3, payload, 0, payload_len);

	if (new_msg_it == 0) {
		auto payload_d = CryptoFirst(payload);
		auto payload_e = CryptoFirst(payload_d);
		bool eq = std::equal(payload_e.cbegin(), payload_e.cend(), payload.cbegin());
		if (eq == false) {
			//Format("First Not eq \n\t{0}\n\t{1}\n\t{2}",
			//	ToHexString(payload  ),
			//	ToHexString(payload_d),
			//	ToHexString(payload_e)  );
		}

		payload = CryptoFirst(payload);
		BlockCopy(payload, 0, decrypted, 3, payload.size());

		if (decrypted[0] == 0x5A && decrypted[1] == 0xA5 && decrypted[2] == 0x1E && decrypted[3] == 0x21 && decrypted[4] == 0x3E && decrypted[5] == 0x5B ) {
			BlockCopy(decrypted, 7, _random_ble_data, 0, 16);
			CalcSha1Key(_name, _random_ble_data);
		}
	}
	else if (new_msg_it > 0 && new_msg_it > _msg_it) {
		auto payload_d = CryptoNext(payload, new_msg_it);
		auto payload_e = CryptoNext(payload_d, new_msg_it);
		bool eq = std::equal(payload_e.cbegin(), payload_e.cend(), payload.cbegin());
		if (eq == false) {
			//Format("Next Not eq \n\t{0}\n\t{1}\n\t{2}",
			//	ToHexString(payload  ),
			//	ToHexString(payload_d),
			//	ToHexString(payload_e)  );
		}

		payload = CryptoNext(payload, new_msg_it);

		BlockCopy(payload, 0, decrypted, 3, payload.size());

		if (decrypted[0] == 0x5A && decrypted[1] == 0xA5 && decrypted[2] == 0x00 && decrypted[3] == 0x21 && decrypted[4] == 0x3E && decrypted[5] == 0x5C && decrypted[6] == 0x01) {
			CalcSha1Key(_random_app_data, _random_ble_data);
		}

		_msg_it = new_msg_it;
	}

	//Format("e string e = \"{0}\";", ToHexString(Data     ));
	//Format("e string d = \"{0}\";", ToHexString(decrypted));
	return decrypted;
}

NinebotCrypto::VarArray NinebotCrypto::Encrypt(const VarArray &Data) {
	std::vector<uint8_t> encrypted; // = new uint8_t[152];
	encrypted.resize(152);

	BlockCopy(Data, 0, encrypted, 0, 3);

	size_t payload_len = Data.size() - 3;

	std::vector<uint8_t> payload;
	payload.resize(payload_len);
	BlockCopy(Data, 3, payload, 0, payload_len);

	if (_msg_it == 0){
		auto crc = CalcCrcFirstMsg(payload);
		payload = CryptoFirst(payload);

		BlockCopy(payload, 0, encrypted, 3, payload.size());

		encrypted[payload_len + 3] = 0;
		encrypted[payload_len + 4] = 0;
		encrypted[payload_len + 5] = crc[0];
		encrypted[payload_len + 6] = crc[1];
		encrypted[payload_len + 7] = 0;
		encrypted[payload_len + 8] = 0;
		encrypted.resize(payload_len + 9);
		_msg_it++;
	}
	else
	{
		_msg_it++;

		auto crc = CalcCrcNextMsg(Data, _msg_it);
		payload = CryptoNext(payload, _msg_it);

		BlockCopy(payload, 0, encrypted, 3, payload.size());

		encrypted[payload_len + 3] = crc[0];
		encrypted[payload_len + 4] = crc[1];
		encrypted[payload_len + 5] = crc[2];
		encrypted[payload_len + 6] = crc[3];
		encrypted[payload_len + 7] = (uint8_t)((_msg_it & 0x0000FF00) >> 8);
		encrypted[payload_len + 8] = (uint8_t)((_msg_it & 0x000000FF) >> 0);
		encrypted.resize(payload_len + 9);

		if (Data[0] == 0x5A && Data[1] == 0xA5 && Data[2] == 0x10 && Data[3] == 0x3E && Data[4] == 0x21 && Data[5] == 0x5C &&Data[6] == 0x00) {
			BlockCopy(Data, 7, _random_app_data, 0, 16);
		}
	}

	//Format("d string d = \"{0}\";", ToHexString(Data     ));
	//Format("d string e = \"{0}\";", ToHexString(encrypted));
	return encrypted;
}
