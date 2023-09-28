#ifndef __BAD_AES_H__
#define __BAD_AES_H__

#include "utils.h"

#include <limits.h>
#include <stdio.h>

#define KEY_SIZE (256 / CHAR_BIT)
#define NK (KEY_SIZE / 4)
#define ROUNDS 14

#if NK != 8
#error "wrong NK size"
#endif

#define BLOCK_SIZE 16
#define BLOCK_ROWS 4

#define XTIME(x) (((x) << 1) ^ ((x) >> 7 ? 0x1b : 0))
#define X3TIME(x) (XTIME(x) ^ (x))

typedef union {
  u8 m[BLOCK_ROWS][BLOCK_ROWS];
  u8 array[BLOCK_SIZE];
  u32 cols[BLOCK_ROWS];
} block_t;

typedef union {
  u8 bytes[4];
  u32 w;
} word_t;

typedef enum : u8 {
  CBC,
  ECB,
} aes_mode_t;

block_t XorBytes(block_t a, block_t b);
block_t SubBytes(block_t b);
block_t ShiftRows(block_t b);
block_t MixColumns(block_t b);
block_t AddRoundKey(block_t b, u32 round_key[BLOCK_ROWS]);
block_t Cipher(block_t b, u32 round_key[BLOCK_ROWS * (ROUNDS + 1)]);
u32 SubWord(u32 word);
void KeyExpansion(u8 key[KEY_SIZE], u32 round_key[BLOCK_ROWS * (ROUNDS + 1)]);

u8 hex_to_byte(char hex);
void print_block(block_t b, FILE *out);

#endif
