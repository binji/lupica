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

void print_op(const char* op) {
  printf(GREEN "%s" WHITE " ", op);
}

Result format_0(uint16_t instr, const char *op) {
  print_op(op);
  return Ok;
}

Result format_n(uint16_t instr, const char* op, const char* fmt) {
  int n = (instr >> 8) & 0xf;
  print_op(op);
  printf(fmt, n);
  return Ok;
}

Result format_nm(uint16_t instr, const char* op, const char* fmt) {
  int n = (instr >> 8) & 0xf;
  int m = (instr >> 4) & 0xf;
  print_op(op);
  printf(fmt, m, n);
  return Ok;
}

Result format_mdn(uint16_t instr, const char* op, const char* fmt, int mul) {
  int n = (instr >> 8) & 0xf;
  int m = (instr >> 4) & 0xf;
  int disp = (instr & 0xf) * mul;
  print_op(op);
  printf(fmt, m, disp, n);
  return Ok;
}

Result format_dmn(uint16_t instr, const char* op, const char* fmt, int mul) {
  int n = (instr >> 8) & 0xf;
  int m = (instr >> 4) & 0xf;
  int disp = (instr & 0xf) * mul;
  print_op(op);
  printf(fmt, disp, m, n);
  return Ok;
}

Result format_nui(uint16_t instr, const char* op, const char* fmt) {
  int n = (instr >> 8) & 0xf;
  uint16_t imm = (instr & 0xff);
  print_op(op);
  printf(fmt, imm, n);
  return Ok;
}

Result format_nsi(uint16_t instr, const char* op, const char* fmt) {
  int n = (instr >> 8) & 0xf;
  int imm = (int)(int16_t)(instr & 0xff);
  print_op(op);
  printf(fmt, imm, n);
  return Ok;
}

Result format_nd4(uint16_t instr, const char* op, const char* fmt, int mul) {
  int n = (instr >> 4) & 0xf;
  int disp = (instr & 0xf) * mul;
  print_op(op);
  printf(fmt, disp, n);
  return Ok;
}

Result format_nd8(uint16_t instr, const char* op, const char* fmt, int mul) {
  int n = (instr >> 8) & 0xf;
  uint16_t disp = (instr & 0xff) * mul;
  print_op(op);
  printf(fmt, disp, n);
  return Ok;
}

Result format_i(uint16_t instr, const char* op, const char* fmt) {
  uint16_t imm = instr & 0xff;
  print_op(op);
  printf(fmt, imm);
  return Ok;
}

Result format_sd(uint16_t instr, const char* op, const char* fmt) {
  uint32_t disp = (int)(int8_t)(instr & 0xff) * 2;
  print_op(op);
  printf(fmt, disp);
  return Ok;
}

Result format_ud(uint16_t instr, const char* op, const char* fmt, int mul) {
  uint32_t disp = (instr & 0xff) * mul;
  print_op(op);
  printf(fmt, disp);
  return Ok;
}

Result format_d12(uint16_t instr, const char* op, const char* fmt) {
  uint32_t disp = (instr & 0xfff) * 2;
  print_op(op);
  printf(fmt, disp);
  return Ok;
}

Result decode(uint16_t instr) {
  switch (instr >> 12) {
  case 0x0:
    // clang-format off
    switch (instr & 0xf) {
      case 0x2:
        switch (instr & 0xf0) {
          case 0x00: return format_n(instr, "STC", "SR, R%u");
          case 0x10: return format_n(instr, "STC", "GBR, R%u");
          case 0x20: return format_n(instr, "STC", "VBR, R%u");
        }
        break;
      case 0x3:
        switch (instr & 0xf0) {
          case 0x00: return format_nm(instr, "BSRF", "R%u");
          case 0x20: return format_nm(instr, "BRAF", "R%u");
        }
        break;
      case 0x4: return format_nm(instr, "MOV.B", "R%u, @(R0, R%u)");
      case 0x5: return format_nm(instr, "MOV.W", "R%u, @(R0, R%u)");
      case 0x6: return format_nm(instr, "MOV.L", "R%u, @(R0, R%u)");
      case 0x7: return format_nm(instr, "MUL.L", "R%u, R%u");
      case 0x8:
        switch (instr) {
          case 0x08: return format_0(instr, "CLRT");
          case 0x18: return format_0(instr, "SETT");
          case 0x28: return format_0(instr, "CLRMAC");
        }
        break;
      case 0x9:
        switch (instr & 0xf0) {
          case 0x00: return format_0(instr, "NOP");
          case 0x10: return format_0(instr, "DIV0U");
          case 0x20: return format_n(instr, "MOVT", "R%u");
        }
        break;
      case 0xa:
        switch (instr & 0xf0) {
          case 0x00: return format_n(instr, "STS", "MACH, R%u");
          case 0x10: return format_n(instr, "STS", "MACL, R%u");
          case 0x20: return format_n(instr, "STS", "PR, R%u");
        }
        break;
      case 0xb: // RTS SLEEP RTE
        switch (instr & 0xf0) {
          case 0x00: return format_0(instr, "RTS");
          case 0x10: return format_0(instr, "SLEEP");
          case 0x20: return format_0(instr, "RTE");
        }
        break;
      case 0xc: return format_nm(instr, "MOV.B", "@(R0, R%u), R%u");
      case 0xd: return format_nm(instr, "MOV.W", "@(R0, R%u), R%u");
      case 0xe: return format_nm(instr, "MOV.L", "@(R0, R%u), R%u");
      case 0xf: return format_nm(instr, "MAC.L", "@R%u+, @R%u+");
    }
    // clang-format on
    return Error;

  case 0x1:
    format_mdn(instr, "MOV.L", "R%u, @(%u, R%u)", 4);
    return Ok;

  case 0x2:
    // clang-format off
    switch (instr & 0xf) {
      case 0x0: return format_nm(instr, "MOV.B", "R%u, @R%u");
      case 0x1: return format_nm(instr, "MOV.W", "R%u, @R%u");
      case 0x2: return format_nm(instr, "MOV.L", "R%u, @R%u");
      case 0x4: return format_nm(instr, "MOV.B", "R%u, @-R%u");
      case 0x5: return format_nm(instr, "MOV.W", "R%u, @-R%u");
      case 0x6: return format_nm(instr, "MOV.L", "R%u, @-R%u");
      case 0x7: return format_nm(instr, "DIV0S", "R%u, R%u");
      case 0x8: return format_nm(instr, "TST", "R%u, R%u");
      case 0x9: return format_nm(instr, "AND", "R%u, R%u");
      case 0xa: return format_nm(instr, "XOR", "R%u, R%u");
      case 0xb: return format_nm(instr, "OR", "R%u, R%u");
      case 0xc: return format_nm(instr, "CMP/STR", "R%u, R%u");
      case 0xd: return format_nm(instr, "XTRCT", "R%u, R%u");
      case 0xe: return format_nm(instr, "MULU.W", "R%u, R%u");
      case 0xf: return format_nm(instr, "MULS.W", "R%u, R%u");
    }
    // clang-format on
    return Error;

  case 0x3:
    // clang-format off
    switch (instr & 0xf) {
      case 0x0: return format_nm(instr, "CMP/EQ", "R%u, R%u");
      case 0x2: return format_nm(instr, "CMP/HS", "R%u, R%u");
      case 0x3: return format_nm(instr, "CMP/GE", "R%u, R%u");
      case 0x4: return format_nm(instr, "DIV1", "R%u, R%u");
      case 0x5: return format_nm(instr, "DMULU.L", "R%u, R%u");
      case 0x6: return format_nm(instr, "CMP/HI", "R%u, R%u");
      case 0x7: return format_nm(instr, "CMP/GT", "R%u, R%u");
      case 0x8: return format_nm(instr, "SUB", "R%u, R%u");
      case 0xa: return format_nm(instr, "SUBC", "R%u, R%u");
      case 0xb: return format_nm(instr, "SUBV", "R%u, R%u");
      case 0xc: return format_nm(instr, "ADD", "R%u, R%u");
      case 0xd: return format_nm(instr, "DMULS.L", "R%u, R%u");
      case 0xe: return format_nm(instr, "ADDC", "R%u, R%u");
      case 0xf: return format_nm(instr, "ADDV", "R%u, R%u");
    }
    // clang-format on
    return Error;

  case 0x4:
    // clang-format off
    switch (instr & 0xff) {
      case 0x00: return format_n(instr, "SHLL", "R%u");
      case 0x01: return format_n(instr, "SHLR", "R%u");
      case 0x02: return format_n(instr, "STS.L", "MACH, @-R%u");
      case 0x03: return format_n(instr, "STC.L", "SR,@ -R%u");
      case 0x04: return format_n(instr, "ROTL", "R%u");
      case 0x05: return format_n(instr, "ROTR", "R%u");
      case 0x06: return format_n(instr, "LDS.L", "@R%u+, MACH");
      case 0x07: return format_n(instr, "LDS.L", "@R%u+, SR");
      case 0x08: return format_n(instr, "SHLL2", "R%u");
      case 0x09: return format_n(instr, "SHLR2", "R%u");
      case 0x0a: return format_n(instr, "LDS", "R%u, MACH");
      case 0x0b: return format_n(instr, "JSR", "@R%u");
      case 0x0e: return format_n(instr, "LDC", "R%u, SR");
      case 0x10: return format_n(instr, "DT", "R%u");
      case 0x11: return format_n(instr, "CMP/PZ", "R%u");
      case 0x12: return format_n(instr, "STS.L", "MACL, @-R%u");
      case 0x13: return format_n(instr, "STC.L", "GBR, @-R%u");
      case 0x15: return format_n(instr, "CMP/PL", "R%u");
      case 0x16: return format_n(instr, "LDS.L", "@R%u+, MACL");
      case 0x17: return format_n(instr, "LDC.L", "@R%u+, GBR");
      case 0x18: return format_n(instr, "SHLL8", "R%u");
      case 0x19: return format_n(instr, "SHLR8", "R%u");
      case 0x1a: return format_n(instr, "LDS", "R%u, MACL");
      case 0x1b: return format_n(instr, "TAS.B", "@R%u");
      case 0x1e: return format_n(instr, "LDC", "R%u, GBR");
      case 0x20: return format_n(instr, "SHAL", "R%u");
      case 0x21: return format_n(instr, "SHAR", "R%u");
      case 0x22: return format_n(instr, "STS.L", "PR, @-R%u");
      case 0x23: return format_n(instr, "STC.L", "VBR, @-R%u");
      case 0x24: return format_n(instr, "ROTCL", "R%u");
      case 0x25: return format_n(instr, "ROTCR", "R%u");
      case 0x26: return format_n(instr, "LDS.L", "@R%u+, PR");
      case 0x27: return format_n(instr, "LDC.L", "@R%u+, VBR");
      case 0x28: return format_n(instr, "SHLL16", "R%u");
      case 0x29: return format_n(instr, "SHLR16", "R%u");
      case 0x2a: return format_n(instr, "LDS", "R%u, PR");
      case 0x2b: return format_n(instr, "JMP", "@R%u");
      case 0x2e: return format_n(instr, "LDC", "R%u, VBR");
    }
    // clang-format on
    return Error;

  case 0x5:
    format_dmn(instr, "MOV.L", "@(%u, R%u), R%u", 4);
    return Ok;

  case 0x6:
    // clang-format off
    switch (instr & 0xf) {
      case 0x0: return format_nm(instr, "MOV.B", "@R%u, R%u");
      case 0x1: return format_nm(instr, "MOV.W", "@R%u, R%u");
      case 0x2: return format_nm(instr, "MOV.L", "@R%u, R%u");
      case 0x3: return format_nm(instr, "MOV", "R%u, R%u");
      case 0x4: return format_nm(instr, "MOV.B", "@R%u+, R%u");
      case 0x5: return format_nm(instr, "MOV.W", "@R%u+, R%u");
      case 0x6: return format_nm(instr, "MOV.L", "@R%u+, R%u");
      case 0x7: return format_nm(instr, "NOT", "R%u, R%u");
      case 0x8: return format_nm(instr, "SWAP.B", "R%u, R%u");
      case 0x9: return format_nm(instr, "SWAP.W", "R%u, R%u");
      case 0xa: return format_nm(instr, "NEGC", "R%u, R%u");
      case 0xb: return format_nm(instr, "NEG", "R%u, R%u");
      case 0xc: return format_nm(instr, "EXTU.B", "R%u, R%u");
      case 0xd: return format_nm(instr, "EXTU.W", "R%u, R%u");
      case 0xe: return format_nm(instr, "EXTS.B", "R%u, R%u");
      case 0xf: return format_nm(instr, "EXTS.W", "R%u, R%u");
    }
    // clang-format on
    return Error;

  case 0x7:
    format_nui(instr, "ADD", "#%d,R%u");
    return Ok;

  case 0x8:
    // clang-format off
    switch (instr & 0x0f00) {
      case 0x000: return format_nd4(instr, "MOV.B", "R0, @(%u, R%u)", 1);
      case 0x100: return format_nd4(instr, "MOV.W", "R0, @(%u, R%u)", 2);
      case 0x400: return format_nd4(instr, "MOV.B", "@(%u, R%u), R0", 1);
      case 0x500: return format_nd4(instr, "MOV.W", "@(%u, R%u), R0", 2);
      case 0x800: return format_i(instr, "CMP/EQ", "#%u, R0");
      case 0x900: return format_sd(instr, "BT", "PC+%08x");
      case 0xb00: return format_sd(instr, "BF", "PC+%08x");
      case 0xd00: return format_sd(instr, "BT/S", "PC+%08x");
      case 0xf00: return format_sd(instr, "BF/S", "PC+%08x");
    }
    // clang-format on
    return Error;

  case 0x9:
    format_nd8(instr, "MOV.W", "@(%u, PC), R%u", 2);
    return Ok;

  case 0xa:
    format_d12(instr, "BRA", "PC+%u");
    return Ok;

  case 0xb:
    format_d12(instr, "BSR", "PC+%08x");
    return Ok;

  case 0xc:
    // clang-format off
    switch (instr & 0x0f00) {
      case 0x0000: return format_ud(instr, "MOV.B", "R0, @(%d, GBR)", 1);
      case 0x0100: return format_ud(instr, "MOV.W", "R0, @(%d, GBR)", 2);
      case 0x0200: return format_ud(instr, "MOV.L", "R0, @(%d, GBR)", 4);
      case 0x0300: return format_i(instr, "TRAPA", "#%d");
      case 0x0400: return format_ud(instr, "MOV.B", "@(%d, GBR), R0", 1);
      case 0x0500: return format_ud(instr, "MOV.W", "@(%d, GBR), R0", 2);
      case 0x0600: return format_ud(instr, "MOV.L", "@(%d, GBR), R0", 4);
      case 0x0700: return format_ud(instr, "MOVA", "@(%d, PC), R0", 4);
      case 0x0800: return format_i(instr, "TST", "#%u, R0");
      case 0x0900: return format_i(instr, "AND", "#%u, R0");
      case 0x0a00: return format_i(instr, "XOR", "#%u, R0");
      case 0x0b00: return format_i(instr, "OR", "#%u, R0");
      case 0x0c00: return format_i(instr, "TST.B", "#%u, @(R0, GBR)");
      case 0x0d00: return format_i(instr, "AND.B", "#%u, @(R0, GBR)");
      case 0x0e00: return format_i(instr, "XOR.B", "#%u, @(R0, GBR)");
      case 0x0f00: return format_i(instr, "OR.B", "#%u, @(R0, GBR)");
    }
    // clang-format on
    return Error;

  case 0xd:
    format_nd8(instr, "MOV.L", "@(%d, PC), R%u", 4);
    return Ok;

  case 0xe:
    format_nsi(instr, "MOV", "#%d, R%u");
    return Ok;

  case 0xf: {
    return Error;
  }

  }

  assert(0);
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

  disassemble(&buffer, 1024*1024, 0);

  return 0;
}
