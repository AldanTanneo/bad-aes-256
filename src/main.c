#define _CRT_SECURE_NO_WARNINGS

#include "bad-aes.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

i32 main(i32 argc, char *argv[]) {
  if (argc < 5) {
    fprintf(stderr, "Usage: bad-aes <mode> <key> <iv> <infile>\n");
    exit(-1);
  }

  aes_mode_t mode = {0};
  if (strcmp(argv[1], "cbc") == 0) {
    mode = CBC;
  } else if (strcmp(argv[1], "ecb") == 0) {
    mode = ECB;
  } else {
    fprintf(stderr, "Invalid mode: '%s'\n", argv[1]);
    exit(-1);
  }

  u8 key[KEY_SIZE] = {0};
  for (usize i = 0; i < KEY_SIZE; ++i) {
    if (argv[2][2 * i] == 0 || argv[2][2 * i + 1] == 0) {
      fprintf(stderr, "Not enough key bytes\n");
      exit(-1);
    }
    u8 a = hex_to_byte(argv[2][2 * i]), b = hex_to_byte(argv[2][2 * i + 1]);
    if (a == 16 || b == 16) {
      fprintf(stderr, "Invalid hex in key: %c%c at index %lu\n", argv[2][i],
              argv[2][i + 1], 2 * i);
      exit(-1);
    }
    key[i] = (a << 4) | b;
  }

  block_t iv = {0};
  if (mode != ECB) {
    for (usize i = 0; i < BLOCK_SIZE; ++i) {
      if (argv[3][2 * i] == 0 || argv[3][2 * i + 1] == 0) {
        fprintf(stderr, "Not enough iv bytes\n");
        exit(-1);
      }
      u8 a = hex_to_byte(argv[3][2 * i]), b = hex_to_byte(argv[3][2 * i + 1]);
      if (a == 16 || b == 16) {
        fprintf(stderr, "Invalid hex in iv: %c%c at index %lu\n", argv[2][i],
                argv[2][i + 1], 2 * i);
        exit(-1);
      }
      iv.array[i] = (a << 4) | b;
    }
  }

  FILE *in = {0};
  if (strcmp(argv[4], "-") == 0) {
    in = stdin;
  } else {
    in = fopen(argv[4], "r");
    if (in == NULL) {
      fprintf(stderr, "Could not open file '%s'\n", argv[4]);
      exit(-1);
    }
  }

  u32 round_key[BLOCK_ROWS * (ROUNDS + 1)] = {0};
  KeyExpansion(key, round_key);

  block_t state = iv;

  while (!feof(in)) {
    block_t current = {0};
    usize read = fread(current.array, sizeof(u8), sizeof(current), in);
    if (read != sizeof(current)) {
      if (ferror(in)) {
        fprintf(stderr, "Encountered error while reading file '%s'\n", argv[4]);
        fclose(in);
        exit(-1);
      } else if (feof(in)) {
        break;
      }
    }
    if (mode == CBC) {
      state = XorBytes(current, state);
    } else if (mode == ECB) {
      state = current;
    }
    state = Cipher(state, round_key);
    if (fwrite(state.array, sizeof(u8), sizeof(state), stdout) !=
        sizeof(state)) {
      fprintf(stderr, "Encountered error while writing to stdout\n");
      fclose(in);
      exit(-1);
    }
  }

  fclose(in);

  return 0;
}
