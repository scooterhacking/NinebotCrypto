#include <cstdint>
#include <cassert>
#include <string>
#include <vector>
#include <array>

class NinebotCrypto {
public:
	typedef std::array <uint8_t, 16> Array16;
	typedef std::vector<uint8_t    > VarArray;

private:
	const Array16 _fw_data = { 0x97, 0xCF, 0xB8, 0x02, 0x84, 0x41, 0x43, 0xDE, 0x56, 0x00, 0x2B, 0x3B, 0x34, 0x78, 0x0A, 0x5D };
	Array16       _random_ble_data;
	Array16       _random_app_data;
	Array16       _sha1_key;
	Array16       _name;
	uint32_t      _msg_it = 0;

	template<typename Container1, typename Container2>
	void BlockCopy(const Container1 &src, const size_t srcOffset, Container2 &dst, const size_t dstOffset, const size_t length) {
		assert(src.size() >= srcOffset + length);
		assert(dst.size() >= dstOffset + length);

		for(size_t idx=0;idx<length; ++idx)
			dst[idx + dstOffset] = src[idx + srcOffset];
	}

	VarArray CryptoFirst(const VarArray &Data);
	VarArray CryptoNext (const VarArray &Data, const uint32_t MsgIt);
	std::array<uint8_t, 2> CalcCrcFirstMsg(const VarArray &Data);
	std::array<uint8_t, 4> CalcCrcNextMsg (const VarArray &Data, const uint32_t MsgIt);

	void CalcSha1Key(const Array16 &Data1, const Array16 &Data2);
	Array16 AesEcbEncrypt(const Array16 &Data, const Array16 &key);
	std::array<uint8_t, 20> Sha1(const std::array<uint8_t, 32> &Data);
	Array16 XOR16(const Array16 &Data1, const Array16 &Data2);

public:
	NinebotCrypto(const std::string Name);
	VarArray Decrypt(const VarArray &Data);
	VarArray Encrypt(const VarArray &Data);
};
