#include <assert.h>
#include <ctype.h>
#include <memory.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define USE_COLOR 1

#if USE_COLOR

#define BLACK "\x1b[30m"
#define BLUE "\x1b[34m"
#define BOLD "\x1b[1m"
#define CYAN "\x1b[36m"
#define DEFAULT "\x1b[0m"
#define GREEN "\x1b[32m"
#define MAGENTA "\x1b[35m"
#define NO_BOLD "\x1b[22m"
#define RED "\x1b[31m"
#define WHITE "\x1b[37m"
#define YELLOW "\x1b[33m"

#else

#define BLACK
#define BLUE
#define BOLD
#define CYAN
#define DEFAULT
#define GREEN
#define MAGENTA
#define NO_BOLD
#define RED
#define WHITE
#define YELLOW

#endif

int g_words[65536];

typedef enum { Ok, Error } Result;

typedef struct Buffer {
  uint8_t *data;
  size_t size;
} Buffer;

uint8_t read_u8(Buffer* buffer, uint32_t address) {
  return buffer->data[address];
}

uint16_t read_u16(Buffer* buffer, uint32_t address) {
  return (buffer->data[address] << 8) | buffer->data[address + 1];
}

uint32_t read_u32(Buffer* buffer, uint32_t address) {
  return (buffer->data[address] << 24) | (buffer->data[address + 1] << 16) |
         (buffer->data[address + 2] << 8) | buffer->data[address + 3];
}

Result read_file(const char* filename, Buffer* buffer) {
  FILE* file = fopen(filename, "rb");
  if (!file) {
    return Error;
  }

  fseek(file, 0, SEEK_END);
  size_t size = ftell(file);
  fseek(file, 0, SEEK_SET);

  buffer->data = malloc(size);
  buffer->size = size;

  size_t read = fread(buffer->data, 1, size, file);
  if (read != size) {
    return Error;
  }

  return Ok;
}

void write_binary_u16(uint16_t x) {
  char buffer[17];
  int i;
  for (i = 0; i < 16; i++) {
    buffer[15 - i] = (x & (1 << i)) ? '1' : '0';
  }
  buffer[16] = 0;
  printf("%s", buffer);
}

uint16_t g_invalid[] = {
};

size_t g_num_invalid = sizeof(g_invalid) / sizeof(g_invalid[0]);

int is_known_invalid(uint16_t instr) {
  size_t j;
  if (((instr & 0xf000) == 0xf000) ||
      ((instr & 0xf000) == 0x0000) ||
      ((instr & 0xf000) == 0x4000) ||
      ((instr & 0xf000) == 0x8000)) {
    return 1;
  }

  for (j = 0; j < g_num_invalid; ++j) {
    if (g_invalid[j] == instr) {
      return 1;
    }
  }
  return 0;
}

void print_words(void) {
  fflush(stdout);
  fprintf(stderr, "\n\n\nWORDS!!!!\n");
  int i = 0;
  int count = 0;
  for (i = 0; i < 65536; ++i) {
    if (is_known_invalid(i)) {
      continue;
    }

    if (g_words[i] == 1) {
      fprintf(stderr, "%04x ", i);
      if (((count + 1) % 8) == 0) {
        fprintf(stderr, "\n");
      }
      ++count;
    }
  }
  fprintf(stderr, "\n\n");
}

void print_op(const char* op) {
  printf(GREEN "%s" WHITE " ", op);
}

void format_0(uint16_t instr, const char *op) { print_op(op); }

void format_n(uint16_t instr, const char* op, const char* fmt) {
  int n = (instr >> 8) & 0xf;
  print_op(op);
  printf(fmt, n);
}

void format_nm(uint16_t instr, const char* op, const char* fmt) {
  int n = (instr >> 8) & 0xf;
  int m = (instr >> 4) & 0xf;
  print_op(op);
  printf(fmt, m, n);
}

void format_mdn(uint16_t instr, const char* op, const char* fmt, int mul) {
  int n = (instr >> 8) & 0xf;
  int m = (instr >> 4) & 0xf;
  int disp = (instr & 0xf) * mul;
  print_op(op);
  printf(fmt, m, disp, n);
}

void format_dmn(uint16_t instr, const char* op, const char* fmt, int mul) {
  int n = (instr >> 8) & 0xf;
  int m = (instr >> 4) & 0xf;
  int disp = (instr & 0xf) * mul;
  print_op(op);
  printf(fmt, disp, m, n);
}

void format_nui(uint16_t instr, const char* op, const char* fmt) {
  int n = (instr >> 8) & 0xf;
  uint16_t imm = (instr & 0xff);
  print_op(op);
  printf(fmt, imm, n);
}

void format_nsi(uint16_t instr, const char* op, const char* fmt) {
  int n = (instr >> 8) & 0xf;
  int imm = (int)(int16_t)(instr & 0xff);
  print_op(op);
  printf(fmt, imm, n);
}

void format_nd4(uint16_t instr, const char* op, const char* fmt, int mul) {
  int n = (instr >> 4) & 0xf;
  int disp = (instr & 0xf) * mul;
  print_op(op);
  printf(fmt, disp, n);
}

void format_nd8(uint16_t instr, const char* op, const char* fmt, int mul) {
  int n = (instr >> 8) & 0xf;
  uint16_t disp = (instr & 0xff) * mul;
  print_op(op);
  printf(fmt, disp, n);
}

void format_i(uint16_t instr, const char* op, const char* fmt) {
  uint16_t imm = instr & 0xff;
  print_op(op);
  printf(fmt, imm);
}

void format_sd(uint16_t instr, const char* op, const char* fmt) {
  uint32_t disp = (int)(int8_t)(instr & 0xff) * 2;
  print_op(op);
  printf(fmt, disp);
}

void format_ud(uint16_t instr, const char* op, const char* fmt, int mul) {
  uint32_t disp = (instr & 0xff) * mul;
  print_op(op);
  printf(fmt, disp);
}

void format_d12(uint16_t instr, const char* op, const char* fmt) {
  uint32_t disp = (instr & 0xfff) * 2;
  print_op(op);
  printf(fmt, disp);
}

Result decode(uint16_t instr) {
  uint8_t top4 = instr >> 12;
  switch (top4) {
  case 0x0:
    if (instr == 0x8) {
      format_0(instr, "CLRT");
      return Ok;
    } else if (instr == 9) {
      format_0(instr, "NOP");
      return Ok;
    } else if (instr == 0xb) {
      format_0(instr, "RTS");
      return Ok;
    } else if (instr == 0x18) {
      format_0(instr, "SETT");
      return Ok;
    } else if (instr == 0x19) {
      format_0(instr, "DIV0U");
      return Ok;
    } else if (instr == 0x1b) {
      format_0(instr, "SLEEP");
      return Ok;
    } else if (instr == 0x28) {
      format_0(instr, "CLRMAC");
      return Ok;
    } else if (instr == 0x2b) {
      format_0(instr, "RTE");
      return Ok;
    } else if ((instr & 0xf) == 4) {
      format_nm(instr, "MOV.B", "R%u,@(R0,R%u)");
      return Ok;
    } else if ((instr & 0xf) == 5) {
      format_nm(instr, "MOV.W", "R%u,@(R0,R%u)");
      return Ok;
    } else if ((instr & 0xf) == 6) {
      format_nm(instr, "MOV.L", "R%u,@(R0,R%u)");
      return Ok;
    } else if ((instr & 0xf) == 7) {
      format_nm(instr, "MUL.L", "R%u,R%u");
      return Ok;
    } else if ((instr & 0xf) == 0xc) {
      format_nm(instr, "MOV.B", "@(R0,R%u),R%u");
      return Ok;
    } else if ((instr & 0xf) == 0xd) {
      format_nm(instr, "MOV.W", "@(R0,R%u),R%u");
      return Ok;
    } else if ((instr & 0xf) == 0xe) {
      format_nm(instr, "MOV.L", "@(R0,R%u),R%u");
      return Ok;
    } else if ((instr & 0xf) == 0xf) {
      format_nm(instr, "MAC.L", "@R%u+,@R%u+");
      return Ok;
    } else if ((instr & 0xff) == 0x02) {
      format_n(instr, "STC", "SR,R%u");
      return Ok;
    } else if ((instr & 0xff) == 0x03) {
      format_nm(instr, "BSRF", "R%u");
      return Ok;
    } else if ((instr & 0xff) == 0x0a) {
      format_n(instr, "STS", "MACH,R%u");
      return Ok;
    } else if ((instr & 0xff) == 0x12) {
      format_n(instr, "STC", "GBR, R%u");
      return Ok;
    } else if ((instr & 0xff) == 0x1a) {
      format_n(instr, "STS", "MACL, R%u");
      return Ok;
    } else if ((instr & 0xff) == 0x22) {
      format_n(instr, "STC", "VBR, R%u");
      return Ok;
    } else if ((instr & 0xff) == 0x23) {
      format_nm(instr, "BRAF", "R%u");
      return Ok;
    } else if ((instr & 0xff) == 0x29) {
      format_n(instr, "MOVT", "R%u");
      return Ok;
    } else if ((instr & 0xff) == 0x2a) {
      format_n(instr, "STS", "PR, R%u");
      return Ok;
    } else {
      return Error;
    }
    break;

  case 0x1:
    format_mdn(instr, "MOV.L", "R%u, @(%u,R%u)", 4);
    return Ok;

  case 0x2:
    if ((instr & 0xf) == 0) {
      format_nm(instr, "MOV.B", "R%u, @R%u");
      return Ok;
    } else if ((instr & 0xf) == 1) {
      format_nm(instr, "MOV.W", "R%u, @R%u");
      return Ok;
    } else if ((instr & 0xf) == 2) {
      format_nm(instr, "MOV.L", "R%u, @R%u");
      return Ok;
    } else if ((instr & 0xf) == 4) {
      format_nm(instr, "MOV.B", "R%u, @-R%u");
      return Ok;
    } else if ((instr & 0xf) == 5) {
      format_nm(instr, "MOV.W", "R%u, @-R%u");
      return Ok;
    } else if ((instr & 0xf) == 6) {
      format_nm(instr, "MOV.L", "R%u, @-R%u");
      return Ok;
    } else if ((instr & 0xf) == 8) {
      format_nm(instr, "TST", "R%u, R%u");
      return Ok;
    } else if ((instr & 0xf) == 9) {
      format_nm(instr, "AND", "R%u, R%u");
      return Ok;
    } else if ((instr & 0xf) == 0xa) {
      format_nm(instr, "XOR", "R%u, R%u");
      return Ok;
    } else if ((instr & 0xf) == 0xb) {
      format_nm(instr, "OR", "R%u, R%u");
      return Ok;
    } else if ((instr & 0xf) == 0xc) {
      format_nm(instr, "CMP/STR", "R%u, R%u");
      return Ok;
    } else if ((instr & 0xf) == 0xe) {
      format_nm(instr, "MULU.W", "R%u, R%u");
      return Ok;
    } else if ((instr & 0xf) == 0xf) {
      format_nm(instr, "MULS.W", "R%u, R%u");
      return Ok;
    }
    break;

  case 0x3: {
    if ((instr & 0xf) == 0) {
      format_nm(instr, "CMP/EQ", "R%u,R%u");
      return Ok;
    } else if ((instr & 0xf) == 2) {
      format_nm(instr, "CMP/HS", "R%u,R%u");
      return Ok;
    } else if ((instr & 0xf) == 3) {
      format_nm(instr, "CMP/GE", "R%u,R%u");
      return Ok;
    } else if ((instr & 0xf) == 4) {
      format_nm(instr, "DIV", "R%u,R%u");
      return Ok;
    } else if ((instr & 0xf) == 6) {
      format_nm(instr, "CMP/HI", "R%u,R%u");
      return Ok;
    } else if ((instr & 0xf) == 7) {
      format_nm(instr, "CMP/GT", "R%u,R%u");
      return Ok;
    } else if ((instr & 0xf) == 8) {
      format_nm(instr, "SUB", "R%u,R%u");
      return Ok;
    } else if ((instr & 0xf) == 0xc) {
      format_nm(instr, "ADD", "R%u,R%u");
      return Ok;
    } else if ((instr & 0xf) == 0xe) {
      format_nm(instr, "ADDC", "R%u,R%u");
      return Ok;
    } else if ((instr & 0xf) == 0xf) {
      format_nm(instr, "ADDV", "R%u,R%u");
      return Ok;
    }
    break;
  }

  case 0x4:
    if ((instr & 0xff) == 0x00) {
      format_n(instr, "SHLL", "R%u");
      return Ok;
    } else if ((instr & 0xff) == 0x01) {
      format_n(instr, "SHLR", "R%u");
      return Ok;
    } else if ((instr & 0xff) == 0x02) {
      format_n(instr, "STS.L", "MACH,@-R%u");
      return Ok;
    } else if ((instr & 0xff) == 0x03) {
      format_n(instr, "STC.L", "SR,@-R%u");
      return Ok;
    } else if ((instr & 0xff) == 0x04) {
      format_n(instr, "ROTL", "R%u");
      return Ok;
    } else if ((instr & 0xff) == 0x05) {
      format_n(instr, "ROTR", "R%u");
      return Ok;
    } else if ((instr & 0xff) == 0x06) {
      format_n(instr, "LDS.L", "@R%u+,MACH");
      return Ok;
    } else if ((instr & 0xff) == 0x07) {
      format_n(instr, "LDS.L", "@R%u+,SR");
      return Ok;
    } else if ((instr & 0xff) == 0x08) {
      format_n(instr, "SHLL2", "R%u");
      return Ok;
    } else if ((instr & 0xff) == 0x09) {
      format_n(instr, "SHLR2", "R%u");
      return Ok;
    } else if ((instr & 0xff) == 0x0a) {
      format_n(instr, "LDS", "R%u,MACH");
      return Ok;
    } else if ((instr & 0xff) == 0x0b) {
      format_n(instr, "JSR", "@R%u");
      return Ok;
    } else if ((instr & 0xff) == 0x0e) {
      format_n(instr, "LDC", "R%u,SR");
      return Ok;
    } else if ((instr & 0xff) == 0x10) {
      format_n(instr, "DT", "R%u");
      return Ok;
    } else if ((instr & 0xff) == 0x11) {
      format_n(instr, "CMP/PZ", "R%u");
      return Ok;
    } else if ((instr & 0xff) == 0x12) {
      format_n(instr, "STS.L", "MACL,@-R%u");
      return Ok;
    } else if ((instr & 0xff) == 0x13) {
      format_n(instr, "STC.L", "GBR,@-R%u");
      return Ok;
    } else if ((instr & 0xff) == 0x15) {
      format_n(instr, "CMP/PL", "R%u");
      return Ok;
    } else if ((instr & 0xff) == 0x16) {
      format_n(instr, "LDS.L", "@R%u+,MACL");
      return Ok;
    } else if ((instr & 0xff) == 0x17) {
      format_n(instr, "LDC.L", "@R%u+,GBR");
      return Ok;
    } else if ((instr & 0xff) == 0x18) {
      format_n(instr, "SHLL8", "R%u");
      return Ok;
    } else if ((instr & 0xff) == 0x19) {
      format_n(instr, "SHLR8", "R%u");
      return Ok;
    } else if ((instr & 0xff) == 0x1a) {
      format_n(instr, "LDS", "R%u,MACL");
      return Ok;
    } else if ((instr & 0xff) == 0x1b) {
      format_n(instr, "TAS.B", "@R%u");
      return Ok;
    } else if ((instr & 0xff) == 0x1e) {
      format_n(instr, "LDC", "R%u,GBR");
      return Ok;
    } else if ((instr & 0xff) == 0x20) {
      format_n(instr, "SHAL", "R%u");
      return Ok;
    } else if ((instr & 0xff) == 0x21) {
      format_n(instr, "SHAR", "R%u");
      return Ok;
    } else if ((instr & 0xff) == 0x22) {
      format_n(instr, "STS.L", "PR,@-R%u");
      return Ok;
    } else if ((instr & 0xff) == 0x23) {
      format_n(instr, "STC.L", "VBR,@-R%u");
      return Ok;
    } else if ((instr & 0xff) == 0x24) {
      format_n(instr, "ROTCL", "R%u");
      return Ok;
    } else if ((instr & 0xff) == 0x25) {
      format_n(instr, "ROTCR", "R%u");
      return Ok;
    } else if ((instr & 0xff) == 0x26) {
      format_n(instr, "LDS.L", "@R%u+,PR");
      return Ok;
    } else if ((instr & 0xff) == 0x27) {
      format_n(instr, "LDC.L", "@R%u+,VBR");
      return Ok;
    } else if ((instr & 0xff) == 0x28) {
      format_n(instr, "SHLL16", "R%u");
      return Ok;
    } else if ((instr & 0xff) == 0x29) {
      format_n(instr, "SHLR16", "R%u");
      return Ok;
    } else if ((instr & 0xff) == 0x2a) {
      format_n(instr, "LDS", "R%u,PR");
      return Ok;
    } else if ((instr & 0xff) == 0x2b) {
      format_n(instr, "JMP", "@R%u");
      return Ok;
    } else if ((instr & 0xff) == 0x2e) {
      format_n(instr, "LDC", "R%u,VBR");
      return Ok;
    } else {
      return Error;
    }
    break;

  case 0x5:
    format_dmn(instr, "MOV.L", "@(%u,R%u),R%u", 4);
    return Ok;

  case 0x6:
    if ((instr & 0xf) == 0x0) {
      format_nm(instr, "MOV.B", "@R%u,R%u");
      return Ok;
    } else if ((instr & 0xf) == 0x1) {
      format_nm(instr, "MOV.W", "@R%u,R%u");
      return Ok;
    } else if ((instr & 0xf) == 0x2) {
      format_nm(instr, "MOV.L", "@R%u,R%u");
      return Ok;
    } else if ((instr & 0xf) == 0x3) {
      format_nm(instr, "MOV.L", "R%u,R%u");
      return Ok;
    } else if ((instr & 0xf) == 0x4) {
      format_nm(instr, "MOV.B", "@R%u+,R%u");
      return Ok;
    } else if ((instr & 0xf) == 0x5) {
      format_nm(instr, "MOV.W", "@R%u+,R%u");
      return Ok;
    } else if ((instr & 0xf) == 0x6) {
      format_nm(instr, "MOV.L", "@R%u+,R%u");
      return Ok;
    } else if ((instr & 0xf) == 0x8) {
      format_nm(instr, "SWAP.B", "R%u,R%u");
      return Ok;
    } else if ((instr & 0xf) == 0xa) {
      format_nm(instr, "NEGC", "R%u,R%u");
      return Ok;
    } else if ((instr & 0xf) == 0xb) {
      format_nm(instr, "NEG", "R%u,R%u");
      return Ok;
    } else if ((instr & 0xf) == 0xc) {
      format_nm(instr, "EXTU.B", "R%u,R%u");
      return Ok;
    } else if ((instr & 0xf) == 0xd) {
      format_nm(instr, "EXTU.W", "R%u,R%u");
      return Ok;
    } else if ((instr & 0xf) == 0xe) {
      format_nm(instr, "EXTS.B", "R%u,R%u");
      return Ok;
    } else if ((instr & 0xf) == 0xf) {
      format_nm(instr, "EXTS.W", "R%u,R%u");
      return Ok;
    }
    break;

  case 0x7:
    format_nui(instr, "ADD", "#%d,R%u");
    return Ok;

  case 0x8:
    if ((instr & 0x0f00) == 0x000) {
      format_nd4(instr, "MOV.B", "R0,@(%u,R%u)", 1);
      return Ok;
    } else if ((instr & 0x0f00) == 0x100) {
      format_nd4(instr, "MOV.W", "R0,@(%u,R%u)", 2);
      return Ok;
    } else if ((instr & 0x0f00) == 0x400) {
      format_nd4(instr, "MOV.B", "@(%u,R%u),R0", 2);
      return Ok;
    } else if ((instr & 0x0f00) == 0x500) {
      format_nd4(instr, "MOV.W", "@(%u,R%u),R0", 2);
      return Ok;
    } else if ((instr & 0x0f00) == 0x800) {
      format_i(instr, "CMP/EQ", "#%u,R0");
      return Ok;
    } else if ((instr & 0x0f00) == 0x900) {
      format_sd(instr, "BT", "PC+%08x");
      return Ok;
    } else if ((instr & 0x0f00) == 0xb00) {
      format_sd(instr, "BF", "PC+%08x");
      return Ok;
    } else if ((instr & 0x0f00) == 0xd00) {
      format_sd(instr, "BT/S", "PC+%08x");
      return Ok;
    } else if ((instr & 0x0f00) == 0xf00) {
      format_sd(instr, "BF/S", "PC+%08x");
      return Ok;
    } else {
      return Error;
    }
    break;

  case 0x9:
    format_nd8(instr, "MOV.W", "@(%u,PC),R%u", 2);
    return Ok;

  case 0xa:
    format_d12(instr, "BRA", "PC+%u");
    return Ok;

  case 0xb:
    format_d12(instr, "BSR", "PC+%08x");
    return Ok;

  case 0xc:
    if ((instr & 0x0f00) == 0x0000) {
      format_ud(instr, "MOV.B", "R0,@(%d,GBR)", 1);
      return Ok;
    } else if ((instr & 0x0f00) == 0x0100) {
      format_ud(instr, "MOV.W", "R0,@(%d,GBR)", 2);
      return Ok;
    } else if ((instr & 0x0f00) == 0x0200) {
      format_ud(instr, "MOV.L", "R0,@(%d,GBR)", 4);
      return Ok;
    } else if ((instr & 0x0f00) == 0x0400) {
      format_ud(instr, "MOV.B", "@(%d,GBR),R0", 2);
      return Ok;
    } else if ((instr & 0x0f00) == 0x0500) {
      format_ud(instr, "MOV.W", "@(%d,GBR),R0", 2);
      return Ok;
    } else if ((instr & 0x0f00) == 0x0600) {
      format_ud(instr, "MOV.L", "@(%d,GBR),R0", 4);
      return Ok;
    } else if ((instr & 0x0f00) == 0x0700) {
      format_ud(instr, "MOVA", "@(%d,PC),R0", 4);
      return Ok;
    } else if ((instr & 0x0f00) == 0x0800) {
      format_i(instr, "TST", "#%u, R0");
      return Ok;
    } else if ((instr & 0x0f00) == 0x0900) {
      format_i(instr, "AND", "#%u, R0");
      return Ok;
    } else if ((instr & 0x0f00) == 0x0a00) {
      format_i(instr, "XOR", "#%u, R0");
      return Ok;
    } else if ((instr & 0x0f00) == 0x0b00) {
      format_i(instr, "OR", "#%u, R0");
      return Ok;
    } else if ((instr & 0x0f00) == 0x0d00) {
      format_i(instr, "AND.B", "#%u, @(R0,GBR)");
      return Ok;
    } else if ((instr & 0x0f00) == 0x0e00) {
      format_i(instr, "XOR.B", "#%u, @(R0,GBR)");
      return Ok;
    } else if ((instr & 0x0f00) == 0x0f00) {
      format_i(instr, "OR.B", "#%u, @(R0,GBR)");
      return Ok;
    }
    break;

  case 0xd:
    format_nd8(instr, "MOV.L", "@(%d,PC),R%u", 4);
    return Ok;

  case 0xe:
    format_nsi(instr, "MOV", "#%d,R%u");
    return Ok;

  case 0xf: {
    return Error;
  }

  }

  return Error;
}

void disassemble(Buffer* buffer, size_t num_instrs, uint32_t address) {
  size_t i;
  for (i = 0; i < num_instrs; ++i, address += 2) {
    uint16_t instr = read_u16(buffer, address);
    printf(RED "[%04x]: " WHITE "%04x ", address, instr);
    write_binary_u16(instr);
    printf(" ");
    if (decode(instr) == Error) {
      g_words[instr] = 1;
      printf(MAGENTA ".WORD %04x" WHITE, instr);
    }

    printf("\n");
  }
}

int main() {
  Buffer buffer;
  if (read_file("anime.bin", &buffer) == Error) {
    fprintf(stderr, "Couldn't read file.\n");
    return 1;
  }

  disassemble(&buffer, 15*2048, 0x480);
  print_words();

  return 0;
}
