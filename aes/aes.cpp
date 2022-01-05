#include <iostream>
#include <vector>
#include <list>
#include <array>
#include <iomanip>
#include <algorithm>

constexpr size_t k_aes_key_size = 16u;
constexpr size_t k_aes_block_size = 16u;
constexpr size_t k_rounds = 10u;

using AesBlock = std::array<uint8_t, k_aes_block_size>;
using AesRoundKey128Bits = std::array<AesBlock, k_rounds>;

/*
 * Round constants
 */
static const uint8_t RCON[k_rounds] =
{
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

int fsb[256] =
    {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

class AES
{
public:
    AES(AesBlock &key)
    {
        std::cout << __func__ << "\n";
        std::copy(key.begin(), key.end(), m_key.begin());
        calcRoundKeys();
    }

    void calcRoundKey(const AesBlock &pre_key, AesBlock &next_key, const size_t round);
    void calcRoundKeys(void);
    static void printKey(const AesBlock &key);
    static void printW(const std::string& name, const uint8_t w[4]);

    void MixColumn(const AesBlock &pre_state, AesBlock &next_key);

    int encrypt(std::array<uint8_t, k_aes_block_size> &plaintext,
                std::array<uint8_t, k_aes_block_size> &ciphertext);

public:
    std::array<uint8_t, k_aes_key_size> m_key;
    AesRoundKey128Bits m_round_key;
};

void AES::printKey(const AesBlock &key)
{
    for (int i : key)
    {
        std::cout << std::setfill('0') << std::setw(2) << std::hex << i;
    }
    std::cout << "\n";
}

void AES::printW(const std::string& name, const uint8_t w[4]) {
    std::cout << name << " = "
              << std::hex << (int)w[0]
              << std::hex << (int)w[1]
              << std::hex << (int)w[2]
              << std::hex << (int)w[3]
              << std::endl;
}

void AES::calcRoundKey(const AesBlock &pre_key, AesBlock &next_key, const size_t round) {
    uint8_t w0[4], w1[4], w2[4], w3[4], w4[4], w5[4], w6[4], w7[4], g_w3[4];

    std::copy(pre_key.begin(), pre_key.begin() + 4, w0);
    std::copy(pre_key.begin() + 4, pre_key.begin() + 8, w1);
    std::copy(pre_key.begin() + 8, pre_key.begin() + 12, w2);
    std::copy(pre_key.begin() + 12, pre_key.begin() + 16, w3);

    uint8_t temp_w3[4];
    temp_w3[0] = w3[1]; temp_w3[1] = w3[2]; temp_w3[2] = w3[3]; temp_w3[3] = w3[0];

    uint8_t sub_w3[4];
    sub_w3[0] = fsb[temp_w3[0]];
    sub_w3[1] = fsb[temp_w3[1]];
    sub_w3[2] = fsb[temp_w3[2]];
    sub_w3[3] = fsb[temp_w3[3]];

    g_w3[0] = sub_w3[0] ^ RCON[round];
    g_w3[1] = sub_w3[1] ^ 0x00;
    g_w3[2] = sub_w3[2] ^ 0x00;
    g_w3[3] = sub_w3[3] ^ 0x00;

    w4[0] = w0[0] ^ g_w3[0];
    w4[1] = w0[1] ^ g_w3[1];
    w4[2] = w0[2] ^ g_w3[2];
    w4[3] = w0[3] ^ g_w3[3];

    w5[0] = w4[0] ^ w1[0];
    w5[1] = w4[1] ^ w1[1];
    w5[2] = w4[2] ^ w1[2];
    w5[3] = w4[3] ^ w1[3];

    w6[0] = w5[0] ^ w2[0];
    w6[1] = w5[1] ^ w2[1];
    w6[2] = w5[2] ^ w2[2];
    w6[3] = w5[3] ^ w2[3];

    w7[0] = w6[0] ^ w3[0];
    w7[1] = w6[1] ^ w3[1];
    w7[2] = w6[2] ^ w3[2];
    w7[3] = w6[3] ^ w3[3];

    std::copy(w4, w4 + 4, next_key.begin());
    std::copy(w5, w5 + 4, next_key.begin() + 4);
    std::copy(w6, w6 + 4, next_key.begin() + 8);
    std::copy(w7, w7 + 4, next_key.begin() + 12);
}

void AES::calcRoundKeys(void)
{
    std::cout << __func__ << "\n";

    std::cout << "Round Key = 0" << "\n";
    printKey(m_key);

    std::cout << "Round Key = 1" << "\n";
    calcRoundKey(m_key, m_round_key.at(0), 0);
    printKey(m_round_key.at(0));

    for (auto i = 1; i < k_rounds; i++) {
        std::cout << "Round Key = " << i << "\n";
        calcRoundKey(m_round_key.at(i - 1), m_round_key.at(i), i);
        printKey(m_round_key.at(i));
    }
}

void AES::MixColumn(const AesBlock &pre_state, AesBlock &next_state) {
    uint8_t row_0[4] = {2, 3, 1, 1};
    uint8_t row_1[4] = {1, 2, 3, 1};
    uint8_t row_2[4] = {1, 1, 2, 3};
    uint8_t row_3[4] = {3, 1, 1, 2};

    const uint8_t *p_row[4] = {row_0, row_1, row_2, row_3};

    for (auto j = 0; j < 16; j++) {
        uint8_t sum = 0x00;
        const uint8_t *row = p_row[j%4];
        const uint8_t *col = pre_state.begin() + 4*(j / 4);

        for (auto i = 0; i < 4; i++) {
            uint8_t t1 = *(col + i);
            const uint8_t t2 = t1;

            if (*row != 1) {
                t1 = (t1 << 1);
                if (t2 & 0x80) {
                    t1 ^= 0x1B;
                }
            }

            if (*row == 3) {
                t1 ^= t2;
            }
            sum ^= t1;
            row++;
        }

        next_state[j] = sum;
    }
}

int AES::encrypt(AesBlock &plaintext, AesBlock &ciphertext)
{
    std::cout << "encrypt\n";

    AesBlock t_block;

    std::cout << "Round 0\n";   // Add RoundKey

    for (int i = 0; i < plaintext.size(); i++) {
        t_block.at(i) = plaintext.at(i) ^ m_key.at(i);
    }

    for (auto j = 1; j < k_rounds + 1; j++) {
        std::cout << "Round " << j <<"\n";
        // Substitution bytes
        std::transform(t_block.begin(), t_block.end(), t_block.begin(),
                    [](uint8_t byte) -> uint8_t { return fsb[byte]; });

        // Shift Row
        AesBlock shift_block = {
            t_block[0], t_block[5], t_block[10], t_block[15],
            t_block[4], t_block[9], t_block[14], t_block[3],
            t_block[8], t_block[13], t_block[2], t_block[7],
            t_block[12], t_block[1], t_block[6], t_block[11]
        };

        // Mix Column
        if (j == k_rounds) {
            t_block = shift_block;
        } else {
            MixColumn(shift_block, t_block);
        }

        // Add Round Key
        for (int i = 0; i < t_block.size(); i++) {
            t_block.at(i) = t_block.at(i) ^ m_round_key.at(j - 1).at(i);
        }

        printKey(t_block);
    }

    ciphertext = t_block;
}

int main(void)
{
    // AesBlock aes_key = {
    //     0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6D, 0x79,
    //     0x20, 0x4B, 0x75, 0x6E, 0x67, 0x20, 0x46, 0x75
    // };

    // AesBlock text = {
    //     0x54, 0x77, 0x6F, 0x20, 0x4F, 0x6E, 0x65, 0x20,
    //     0x4E, 0x69, 0x6E, 0x65, 0x20, 0x54, 0x77, 0x6F
    // };

    // AesBlock expected_cipher = {
    //     0x29, 0xC3, 0x50, 0x5F, 0x57, 0x14, 0x20, 0xF6,
    //     0x40, 0x22, 0x99, 0xB3, 0x1A, 0x02, 0xD7, 0x3A
    // };

    AesBlock aes_key = {
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    AesBlock text = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    AesBlock expected_cipher = {
        0x0e, 0xdd, 0x33, 0xd3, 0xc6, 0x21, 0xe5, 0x46,
        0x45, 0x5b, 0xd8, 0xba, 0x14, 0x18, 0xbe, 0xc8
    };

    AesBlock ciphertext;

    AES aes(aes_key);
    aes.encrypt(text, ciphertext);

    AES::printKey(ciphertext);

    if (std::equal(ciphertext.begin(), ciphertext.end(), expected_cipher.begin())) {
        std::cout << "expected and ciphertext are equal\n";
    } else {
        std::cout << "expected and ciphertext aren't equal\n";
    }

    return 0;
}