#include "md5.h"
#include <iomanip>
#include <assert.h>
#include <chrono>
#include <vector>

#ifdef __aarch64__
#include <arm_neon.h>
#endif

using namespace std;
using namespace chrono;

/**
 * StringProcess: 将单个输入字符串转换成MD5计算所需的消息数组
 * @param input 输入
 * @param[out] n_byte 用于给调用者传递额外的返回值，即最终Byte数组的长度
 * @return Byte消息数组
 */
Byte *StringProcess(string input, int *n_byte)
{
	// 将输入的字符串转换为Byte为单位的数组
	Byte *blocks = (Byte *)input.c_str();
	int length = input.length();

	// 计算原始消息长度（以比特为单位）
	int bitLength = length * 8;

	// paddingBits: 原始消息需要的padding长度（以bit为单位）
	// 对于给定的消息，将其补齐至length%512==448为止
	// 需要注意的是，即便给定的消息满足length%512==448，也需要再pad 512bits
	int paddingBits = bitLength % 512;
	if (paddingBits > 448)
	{
		paddingBits = 512 - (paddingBits - 448);
	}
	else if (paddingBits < 448)
	{
		paddingBits = 448 - paddingBits;
	}
	else if (paddingBits == 448)
	{
		paddingBits = 512;
	}

	// 原始消息需要的padding长度（以Byte为单位）
	int paddingBytes = paddingBits / 8;
	// 创建最终的字节数组
	// length + paddingBytes + 8:
	// 1. length为原始消息的长度（bits）
	// 2. paddingBytes为原始消息需要的padding长度（Bytes）
	// 3. 在pad到length%512==448之后，需要额外附加64bits的原始消息长度，即8个bytes
	int paddedLength = length + paddingBytes + 8;
	Byte *paddedMessage = new Byte[paddedLength];

	// 复制原始消息
	memcpy(paddedMessage, blocks, length);

	// 添加填充字节。填充时，第一位为1，后面的所有位均为0。
	// 所以第一个byte是0x80
	paddedMessage[length] = 0x80;							 // 添加一个0x80字节
	memset(paddedMessage + length + 1, 0, paddingBytes - 1); // 填充0字节

	// 添加消息长度（64比特，小端格式）
	for (int i = 0; i < 8; ++i)
	{
		// 特别注意此处应当将bitLength转换为uint64_t
		// 这里的length是原始消息的长度
		paddedMessage[length + paddingBytes + i] = ((uint64_t)length * 8 >> (i * 8)) & 0xFF;
	}

	// 验证长度是否满足要求。此时长度应当是512bit的倍数
	int residual = 8 * paddedLength % 512;
	// assert(residual == 0);

	// 在填充+添加长度之后，消息被分为n_blocks个512bit的部分
	*n_byte = paddedLength;
	return paddedMessage;
}


/**
 * MD5Hash: 将单个输入字符串转换成MD5
 * @param input 输入
 * @param[out] state 用于给调用者传递额外的返回值，即最终的缓冲区，也就是MD5的结果
 * @return Byte消息数组
 */
void MD5Hash(string input, bit32 *state)
{

	Byte *paddedMessage;
	int *messageLength = new int[1];
	for (int i = 0; i < 1; i += 1)
	{
		paddedMessage = StringProcess(input, &messageLength[i]);
		// cout<<messageLength[i]<<endl;
		assert(messageLength[i] == messageLength[0]);
	}
	int n_blocks = messageLength[0] / 64;

	// bit32* state= new bit32[4];
	state[0] = 0x67452301;
	state[1] = 0xefcdab89;
	state[2] = 0x98badcfe;
	state[3] = 0x10325476;

	// 逐block地更新state
	for (int i = 0; i < n_blocks; i += 1)
	{
		bit32 x[16];

		// 下面的处理，在理解上较为复杂
		for (int i1 = 0; i1 < 16; ++i1)
		{
			x[i1] = (paddedMessage[4 * i1 + i * 64]) |
					(paddedMessage[4 * i1 + 1 + i * 64] << 8) |
					(paddedMessage[4 * i1 + 2 + i * 64] << 16) |
					(paddedMessage[4 * i1 + 3 + i * 64] << 24);
		}

		bit32 a = state[0], b = state[1], c = state[2], d = state[3];

		auto start = system_clock::now();
		/* Round 1 */
		FF(a, b, c, d, x[0], s11, 0xd76aa478);
		FF(d, a, b, c, x[1], s12, 0xe8c7b756);
		FF(c, d, a, b, x[2], s13, 0x242070db);
		FF(b, c, d, a, x[3], s14, 0xc1bdceee);
		FF(a, b, c, d, x[4], s11, 0xf57c0faf);
		FF(d, a, b, c, x[5], s12, 0x4787c62a);
		FF(c, d, a, b, x[6], s13, 0xa8304613);
		FF(b, c, d, a, x[7], s14, 0xfd469501);
		FF(a, b, c, d, x[8], s11, 0x698098d8);
		FF(d, a, b, c, x[9], s12, 0x8b44f7af);
		FF(c, d, a, b, x[10], s13, 0xffff5bb1);
		FF(b, c, d, a, x[11], s14, 0x895cd7be);
		FF(a, b, c, d, x[12], s11, 0x6b901122);
		FF(d, a, b, c, x[13], s12, 0xfd987193);
		FF(c, d, a, b, x[14], s13, 0xa679438e);
		FF(b, c, d, a, x[15], s14, 0x49b40821);

		/* Round 2 */
		GG(a, b, c, d, x[1], s21, 0xf61e2562);
		GG(d, a, b, c, x[6], s22, 0xc040b340);
		GG(c, d, a, b, x[11], s23, 0x265e5a51);
		GG(b, c, d, a, x[0], s24, 0xe9b6c7aa);
		GG(a, b, c, d, x[5], s21, 0xd62f105d);
		GG(d, a, b, c, x[10], s22, 0x2441453);
		GG(c, d, a, b, x[15], s23, 0xd8a1e681);
		GG(b, c, d, a, x[4], s24, 0xe7d3fbc8);
		GG(a, b, c, d, x[9], s21, 0x21e1cde6);
		GG(d, a, b, c, x[14], s22, 0xc33707d6);
		GG(c, d, a, b, x[3], s23, 0xf4d50d87);
		GG(b, c, d, a, x[8], s24, 0x455a14ed);
		GG(a, b, c, d, x[13], s21, 0xa9e3e905);
		GG(d, a, b, c, x[2], s22, 0xfcefa3f8);
		GG(c, d, a, b, x[7], s23, 0x676f02d9);
		GG(b, c, d, a, x[12], s24, 0x8d2a4c8a);

		/* Round 3 */
		HH(a, b, c, d, x[5], s31, 0xfffa3942);
		HH(d, a, b, c, x[8], s32, 0x8771f681);
		HH(c, d, a, b, x[11], s33, 0x6d9d6122);
		HH(b, c, d, a, x[14], s34, 0xfde5380c);
		HH(a, b, c, d, x[1], s31, 0xa4beea44);
		HH(d, a, b, c, x[4], s32, 0x4bdecfa9);
		HH(c, d, a, b, x[7], s33, 0xf6bb4b60);
		HH(b, c, d, a, x[10], s34, 0xbebfbc70);
		HH(a, b, c, d, x[13], s31, 0x289b7ec6);
		HH(d, a, b, c, x[0], s32, 0xeaa127fa);
		HH(c, d, a, b, x[3], s33, 0xd4ef3085);
		HH(b, c, d, a, x[6], s34, 0x4881d05);
		HH(a, b, c, d, x[9], s31, 0xd9d4d039);
		HH(d, a, b, c, x[12], s32, 0xe6db99e5);
		HH(c, d, a, b, x[15], s33, 0x1fa27cf8);
		HH(b, c, d, a, x[2], s34, 0xc4ac5665);

		/* Round 4 */
		II(a, b, c, d, x[0], s41, 0xf4292244);
		II(d, a, b, c, x[7], s42, 0x432aff97);
		II(c, d, a, b, x[14], s43, 0xab9423a7);
		II(b, c, d, a, x[5], s44, 0xfc93a039);
		II(a, b, c, d, x[12], s41, 0x655b59c3);
		II(d, a, b, c, x[3], s42, 0x8f0ccc92);
		II(c, d, a, b, x[10], s43, 0xffeff47d);
		II(b, c, d, a, x[1], s44, 0x85845dd1);
		II(a, b, c, d, x[8], s41, 0x6fa87e4f);
		II(d, a, b, c, x[15], s42, 0xfe2ce6e0);
		II(c, d, a, b, x[6], s43, 0xa3014314);
		II(b, c, d, a, x[13], s44, 0x4e0811a1);
		II(a, b, c, d, x[4], s41, 0xf7537e82);
		II(d, a, b, c, x[11], s42, 0xbd3af235);
		II(c, d, a, b, x[2], s43, 0x2ad7d2bb);
		II(b, c, d, a, x[9], s44, 0xeb86d391);

		state[0] += a;
		state[1] += b;
		state[2] += c;
		state[3] += d;
	}

	// 下面的处理，在理解上较为复杂
	for (int i = 0; i < 4; i++)
	{
		uint32_t value = state[i];
		state[i] = ((value & 0xff) << 24) |		 // 将最低字节移到最高位
				   ((value & 0xff00) << 8) |	 // 将次低字节左移
				   ((value & 0xff0000) >> 8) |	 // 将次高字节右移
				   ((value & 0xff000000) >> 24); // 将最高字节移到最低位
	}

	// 输出最终的hash结果
	// for (int i1 = 0; i1 < 4; i1 += 1)
	// {
	// 	cout << std::setw(8) << std::setfill('0') << hex << state[i1];
	// }
	// cout << endl;

	// 释放动态分配的内存
	// 实现SIMD并行算法的时候，也请记得及时回收内存！
	delete[] paddedMessage;
	delete[] messageLength;
}




#ifdef __aarch64__

// 防止编译器认为哈希结果没有被使用，从而优化掉计算过程
static volatile bit32 md5_simd_sink = 0;

static inline uint32x4_t md5_f4(uint32x4_t x, uint32x4_t y, uint32x4_t z)
{
    return vorrq_u32(vandq_u32(x, y), vandq_u32(vmvnq_u32(x), z));
}

static inline uint32x4_t md5_g4(uint32x4_t x, uint32x4_t y, uint32x4_t z)
{
    return vorrq_u32(vandq_u32(x, z), vandq_u32(y, vmvnq_u32(z)));
}

static inline uint32x4_t md5_h4(uint32x4_t x, uint32x4_t y, uint32x4_t z)
{
    return veorq_u32(veorq_u32(x, y), z);
}

static inline uint32x4_t md5_i4(uint32x4_t x, uint32x4_t y, uint32x4_t z)
{
    return veorq_u32(y, vorrq_u32(x, vmvnq_u32(z)));
}

// n 是常量，因此使用 _n 版本移位，编译器更容易生成高效指令
#define ROTL4(v, n) \
    vorrq_u32(vshlq_n_u32((v), (n)), vshrq_n_u32((v), 32 - (n)))

#define STEP_F4(a, b, c, d, x, s, ac) {       \
    (a) = vaddq_u32((a), md5_f4((b), (c), (d))); \
    (a) = vaddq_u32((a), (x));                   \
    (a) = vaddq_u32((a), vdupq_n_u32(ac));       \
    (a) = ROTL4((a), (s));                       \
    (a) = vaddq_u32((a), (b));                   \
}

#define STEP_G4(a, b, c, d, x, s, ac) {       \
    (a) = vaddq_u32((a), md5_g4((b), (c), (d))); \
    (a) = vaddq_u32((a), (x));                   \
    (a) = vaddq_u32((a), vdupq_n_u32(ac));       \
    (a) = ROTL4((a), (s));                       \
    (a) = vaddq_u32((a), (b));                   \
}

#define STEP_H4(a, b, c, d, x, s, ac) {       \
    (a) = vaddq_u32((a), md5_h4((b), (c), (d))); \
    (a) = vaddq_u32((a), (x));                   \
    (a) = vaddq_u32((a), vdupq_n_u32(ac));       \
    (a) = ROTL4((a), (s));                       \
    (a) = vaddq_u32((a), (b));                   \
}

#define STEP_I4(a, b, c, d, x, s, ac) {       \
    (a) = vaddq_u32((a), md5_i4((b), (c), (d))); \
    (a) = vaddq_u32((a), (x));                   \
    (a) = vaddq_u32((a), vdupq_n_u32(ac));       \
    (a) = ROTL4((a), (s));                       \
    (a) = vaddq_u32((a), (b));                   \
}


// 只处理长度 <= 55 的口令。
// 因为这种口令填充后只需要一个 512-bit block。
static inline void build_one_block(const string& s, bit32 out[16])
{
    for (int i = 0; i < 16; i++)
    {
        out[i] = 0;
    }

    const int len = (int)s.length();

    for (int i = 0; i < len; i++)
    {
        int word_id = i >> 2;
        int shift = (i & 3) << 3;
        out[word_id] |= ((bit32)(unsigned char)s[i]) << shift;
    }

    int pad_word = len >> 2;
    int pad_shift = (len & 3) << 3;
    out[pad_word] |= ((bit32)0x80) << pad_shift;

    out[14] = (bit32)(len * 8);
    out[15] = 0;
}


static void MD5Hash4_NEON_FAST(const string& s0,
                               const string& s1,
                               const string& s2,
                               const string& s3,
                               bit32 digest[4][4])
{
    bit32 w0[16], w1[16], w2[16], w3[16];

    build_one_block(s0, w0);
    build_one_block(s1, w1);
    build_one_block(s2, w2);
    build_one_block(s3, w3);

    uint32x4_t x[16];

    // 这里手动展开 16 个消息字，减少循环和临时数组开销
    x[0]  = (uint32x4_t){w0[0],  w1[0],  w2[0],  w3[0]};
    x[1]  = (uint32x4_t){w0[1],  w1[1],  w2[1],  w3[1]};
    x[2]  = (uint32x4_t){w0[2],  w1[2],  w2[2],  w3[2]};
    x[3]  = (uint32x4_t){w0[3],  w1[3],  w2[3],  w3[3]};
    x[4]  = (uint32x4_t){w0[4],  w1[4],  w2[4],  w3[4]};
    x[5]  = (uint32x4_t){w0[5],  w1[5],  w2[5],  w3[5]};
    x[6]  = (uint32x4_t){w0[6],  w1[6],  w2[6],  w3[6]};
    x[7]  = (uint32x4_t){w0[7],  w1[7],  w2[7],  w3[7]};
    x[8]  = (uint32x4_t){w0[8],  w1[8],  w2[8],  w3[8]};
    x[9]  = (uint32x4_t){w0[9],  w1[9],  w2[9],  w3[9]};
    x[10] = (uint32x4_t){w0[10], w1[10], w2[10], w3[10]};
    x[11] = (uint32x4_t){w0[11], w1[11], w2[11], w3[11]};
    x[12] = (uint32x4_t){w0[12], w1[12], w2[12], w3[12]};
    x[13] = (uint32x4_t){w0[13], w1[13], w2[13], w3[13]};
    x[14] = (uint32x4_t){w0[14], w1[14], w2[14], w3[14]};
    x[15] = (uint32x4_t){w0[15], w1[15], w2[15], w3[15]};

    const uint32x4_t A0 = vdupq_n_u32(0x67452301);
    const uint32x4_t B0 = vdupq_n_u32(0xefcdab89);
    const uint32x4_t C0 = vdupq_n_u32(0x98badcfe);
    const uint32x4_t D0 = vdupq_n_u32(0x10325476);

    uint32x4_t a = A0;
    uint32x4_t b = B0;
    uint32x4_t c = C0;
    uint32x4_t d = D0;

    // Round 1
    STEP_F4(a, b, c, d, x[0],  s11, 0xd76aa478);
    STEP_F4(d, a, b, c, x[1],  s12, 0xe8c7b756);
    STEP_F4(c, d, a, b, x[2],  s13, 0x242070db);
    STEP_F4(b, c, d, a, x[3],  s14, 0xc1bdceee);
    STEP_F4(a, b, c, d, x[4],  s11, 0xf57c0faf);
    STEP_F4(d, a, b, c, x[5],  s12, 0x4787c62a);
    STEP_F4(c, d, a, b, x[6],  s13, 0xa8304613);
    STEP_F4(b, c, d, a, x[7],  s14, 0xfd469501);
    STEP_F4(a, b, c, d, x[8],  s11, 0x698098d8);
    STEP_F4(d, a, b, c, x[9],  s12, 0x8b44f7af);
    STEP_F4(c, d, a, b, x[10], s13, 0xffff5bb1);
    STEP_F4(b, c, d, a, x[11], s14, 0x895cd7be);
    STEP_F4(a, b, c, d, x[12], s11, 0x6b901122);
    STEP_F4(d, a, b, c, x[13], s12, 0xfd987193);
    STEP_F4(c, d, a, b, x[14], s13, 0xa679438e);
    STEP_F4(b, c, d, a, x[15], s14, 0x49b40821);

    // Round 2
    STEP_G4(a, b, c, d, x[1],  s21, 0xf61e2562);
    STEP_G4(d, a, b, c, x[6],  s22, 0xc040b340);
    STEP_G4(c, d, a, b, x[11], s23, 0x265e5a51);
    STEP_G4(b, c, d, a, x[0],  s24, 0xe9b6c7aa);
    STEP_G4(a, b, c, d, x[5],  s21, 0xd62f105d);
    STEP_G4(d, a, b, c, x[10], s22, 0x02441453);
    STEP_G4(c, d, a, b, x[15], s23, 0xd8a1e681);
    STEP_G4(b, c, d, a, x[4],  s24, 0xe7d3fbc8);
    STEP_G4(a, b, c, d, x[9],  s21, 0x21e1cde6);
    STEP_G4(d, a, b, c, x[14], s22, 0xc33707d6);
    STEP_G4(c, d, a, b, x[3],  s23, 0xf4d50d87);
    STEP_G4(b, c, d, a, x[8],  s24, 0x455a14ed);
    STEP_G4(a, b, c, d, x[13], s21, 0xa9e3e905);
    STEP_G4(d, a, b, c, x[2],  s22, 0xfcefa3f8);
    STEP_G4(c, d, a, b, x[7],  s23, 0x676f02d9);
    STEP_G4(b, c, d, a, x[12], s24, 0x8d2a4c8a);

    // Round 3
    STEP_H4(a, b, c, d, x[5],  s31, 0xfffa3942);
    STEP_H4(d, a, b, c, x[8],  s32, 0x8771f681);
    STEP_H4(c, d, a, b, x[11], s33, 0x6d9d6122);
    STEP_H4(b, c, d, a, x[14], s34, 0xfde5380c);
    STEP_H4(a, b, c, d, x[1],  s31, 0xa4beea44);
    STEP_H4(d, a, b, c, x[4],  s32, 0x4bdecfa9);
    STEP_H4(c, d, a, b, x[7],  s33, 0xf6bb4b60);
    STEP_H4(b, c, d, a, x[10], s34, 0xbebfbc70);
    STEP_H4(a, b, c, d, x[13], s31, 0x289b7ec6);
    STEP_H4(d, a, b, c, x[0],  s32, 0xeaa127fa);
    STEP_H4(c, d, a, b, x[3],  s33, 0xd4ef3085);
    STEP_H4(b, c, d, a, x[6],  s34, 0x04881d05);
    STEP_H4(a, b, c, d, x[9],  s31, 0xd9d4d039);
    STEP_H4(d, a, b, c, x[12], s32, 0xe6db99e5);
    STEP_H4(c, d, a, b, x[15], s33, 0x1fa27cf8);
    STEP_H4(b, c, d, a, x[2],  s34, 0xc4ac5665);

    // Round 4
    STEP_I4(a, b, c, d, x[0],  s41, 0xf4292244);
    STEP_I4(d, a, b, c, x[7],  s42, 0x432aff97);
    STEP_I4(c, d, a, b, x[14], s43, 0xab9423a7);
    STEP_I4(b, c, d, a, x[5],  s44, 0xfc93a039);
    STEP_I4(a, b, c, d, x[12], s41, 0x655b59c3);
    STEP_I4(d, a, b, c, x[3],  s42, 0x8f0ccc92);
    STEP_I4(c, d, a, b, x[10], s43, 0xffeff47d);
    STEP_I4(b, c, d, a, x[1],  s44, 0x85845dd1);
    STEP_I4(a, b, c, d, x[8],  s41, 0x6fa87e4f);
    STEP_I4(d, a, b, c, x[15], s42, 0xfe2ce6e0);
    STEP_I4(c, d, a, b, x[6],  s43, 0xa3014314);
    STEP_I4(b, c, d, a, x[13], s44, 0x4e0811a1);
    STEP_I4(a, b, c, d, x[4],  s41, 0xf7537e82);
    STEP_I4(d, a, b, c, x[11], s42, 0xbd3af235);
    STEP_I4(c, d, a, b, x[2],  s43, 0x2ad7d2bb);
    STEP_I4(b, c, d, a, x[9],  s44, 0xeb86d391);

    a = vaddq_u32(a, A0);
    b = vaddq_u32(b, B0);
    c = vaddq_u32(c, C0);
    d = vaddq_u32(d, D0);

    bit32 oa[4], ob[4], oc[4], od[4];

    vst1q_u32(oa, a);
    vst1q_u32(ob, b);
    vst1q_u32(oc, c);
    vst1q_u32(od, d);

    for (int lane = 0; lane < 4; lane++)
    {
        digest[lane][0] = oa[lane];
        digest[lane][1] = ob[lane];
        digest[lane][2] = oc[lane];
        digest[lane][3] = od[lane];

        for (int j = 0; j < 4; j++)
        {
            bit32 value = digest[lane][j];
            digest[lane][j] = ((value & 0xff) << 24) |
                              ((value & 0xff00) << 8) |
                              ((value & 0xff0000) >> 8) |
                              ((value & 0xff000000) >> 24);
        }
    }

    md5_simd_sink ^= digest[0][0];
}


// 批量哈希接口。
// results == nullptr 时，只用于性能测试；
// results != nullptr 时，会保存每个口令的结果，给 correctness.cpp 用。
void MD5HashBatchSIMD(
    const vector<string>& passwords,
    vector<array<bit32, 4>>* results
)
{
    if (results != nullptr)
    {
        results->clear();
        results->reserve(passwords.size());
    }

    const string* group[4];
    int group_count = 0;

    bit32 simd_state[4][4];
    bit32 serial_state[4];

    auto save_serial_result = [&](bit32 state[4])
    {
        if (results != nullptr)
        {
            array<bit32, 4> one;
            one[0] = state[0];
            one[1] = state[1];
            one[2] = state[2];
            one[3] = state[3];
            results->push_back(one);
        }

        md5_simd_sink ^= state[0];
    };

    auto flush_short_group = [&]()
    {
        if (group_count == 4)
        {
            MD5Hash4_NEON_FAST(
                *group[0],
                *group[1],
                *group[2],
                *group[3],
                simd_state
            );

            if (results != nullptr)
            {
                for (int lane = 0; lane < 4; lane++)
                {
                    array<bit32, 4> one;
                    one[0] = simd_state[lane][0];
                    one[1] = simd_state[lane][1];
                    one[2] = simd_state[lane][2];
                    one[3] = simd_state[lane][3];
                    results->push_back(one);
                }
            }

            md5_simd_sink ^= simd_state[0][0];
            md5_simd_sink ^= simd_state[1][0];
            md5_simd_sink ^= simd_state[2][0];
            md5_simd_sink ^= simd_state[3][0];

            group_count = 0;
        }
    };

    for (const string& pw : passwords)
    {
        if (pw.length() <= 55)
        {
            group[group_count] = &pw;
            group_count++;

            flush_short_group();
        }
        else
        {
            for (int i = 0; i < group_count; i++)
            {
                MD5Hash(*group[i], serial_state);
                save_serial_result(serial_state);
            }
            group_count = 0;

            MD5Hash(pw, serial_state);
            save_serial_result(serial_state);
        }
    }

    for (int i = 0; i < group_count; i++)
    {
        MD5Hash(*group[i], serial_state);
        save_serial_result(serial_state);
    }
}
#else

// 非 ARM 环境走串行，方便 Windows 本地编译和测试
void MD5HashBatchSIMD(
    const vector<string>& passwords,
    vector<array<bit32, 4>>* results
)
{
    bit32 state[4];

    if (results != nullptr)
    {
        results->clear();
        results->reserve(passwords.size());
    }

    for (const string& pw : passwords)
    {
        MD5Hash(pw, state);

        if (results != nullptr)
        {
            array<bit32, 4> one;
            one[0] = state[0];
            one[1] = state[1];
            one[2] = state[2];
            one[3] = state[3];
            results->push_back(one);
        }
    }
}

#endif