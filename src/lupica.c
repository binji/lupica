#include <assert.h>
#include <ctype.h>
#include <memory.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

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

Result decode(uint16_t instr) {
  uint8_t top4 = instr >> 12;
  switch (top4) {
  case 0x0:
    if (instr == 9) {
      printf("NOP");
      return Ok;
    } else if (instr == 0xb) {
      printf("RTS");
      return Ok;
    } else if ((instr & 0xf) == 4) {
      int n = (instr >> 8) & 0xf;
      int m = (instr >> 4) & 0xf;
      printf("MOV.B R%u,@(R0,R%u)", m, n);
      return Ok;
    } else if ((instr & 0xf) == 5) {
      int n = (instr >> 8) & 0xf;
      int m = (instr >> 4) & 0xf;
      printf("MOV.W R%u,@(R0,R%u)", m, n);
      return Ok;
    } else if ((instr & 0xff) == 0x2) {
      int n = (instr >> 8) & 0xf;
      printf("STC SR,R%u", n);
      return Ok;
    } else {
      return Error;
    }
    break;

  case 0x1: {
    int n = (instr >> 8) & 0xf;
    int m = (instr >> 4) & 0xf;
    int disp = (instr & 0xf) * 4;
    printf("MOV.L R%u, @(%u, R%u)", m, disp, n);
    return Ok;
  }

  case 0x2: {
    int n = (instr >> 8) & 0xf;
    int m = (instr >> 4) & 0xf;
    if ((instr & 0xf) == 0) {
      printf("MOV.B R%u, @R%u", m, n);
      return Ok;
    } else if ((instr & 0xf) == 1) {
      printf("MOV.W R%u, @R%u", m, n);
      return Ok;
    } else if ((instr & 0xf) == 2) {
      printf("MOV.L R%u, @R%u", m, n);
      return Ok;
    } else if ((instr & 0xf) == 6) {
      printf("MOV.L R%u, @-R%u", m, n);
      return Ok;
    } else if ((instr & 0xf) == 8) {
      printf("TST R%u, R%u", m, n);
      return Ok;
    } else if ((instr & 0xf) == 9) {
      printf("AND R%u, R%u", m, n);
      return Ok;
    }
    break;
  }

  case 0x3: {
    int n = (instr >> 8) & 0xf;
    int m = (instr >> 4) & 0xf;
    if ((instr & 0xf) == 0) {
      printf("CMP/EQ R%u,R%u", m, n);
      return Ok;
    } else if ((instr & 0xf) == 3) {
      printf("CMP/GE R%u,R%u", m, n);
      return Ok;
    } else if ((instr & 0xf) == 0xc) {
      printf("ADD R%u,R%u", m, n);
      return Ok;
    }
    break;
  }

  case 0x4:
    if ((instr & 0xff) == 0x27) {
      int m = (instr >> 8) & 0xf;
      printf("LCD.L @R%u+,VBR", m);
      return Ok;
    } else if ((instr & 0xff) == 0x08) {
      int m = (instr >> 8) & 0xf;
      printf("SHLL2 R%u", m);
      return Ok;
    } else if ((instr & 0xff) == 0x0b) {
      int m = (instr >> 8) & 0xf;
      printf("JSR @R%u", m);
      return Ok;
    } else if ((instr & 0xff) == 0x1e) {
      int m = (instr >> 8) & 0xf;
      printf("LDC R%u,GBR", m);
      return Ok;
    } else if ((instr & 0xff) == 0x22) {
      int n = (instr >> 8) & 0xf;
      printf("STS.L PR,@-R%u", n);
      return Ok;
    } else if ((instr & 0xff) == 0x26) {
      int m = (instr >> 8) & 0xf;
      printf("LDS.L @R%u+,PR", m);
      return Ok;
    } else if ((instr & 0xff) == 0x2b) {
      int m = (instr >> 8) & 0xf;
      printf("JMP @R%u", m);
      return Ok;
    } else {
      return Error;
    }
    break;

  case 0x5: {
    int n = (instr >> 8) & 0xf;
    int m = (instr >> 4) & 0xf;
    int disp = (instr & 0xf) * 4;
    printf("MOV.L @(%u,R%u),R%u", disp, m, n);
    return Ok;
  }

  case 0x6: {
    int n = (instr >> 8) & 0xf;
    int m = (instr >> 4) & 0xf;
    if ((instr & 0xf) == 0x1) {
      printf("MOV.W @R%u,R%u", m, n);
      return Ok;
    } else if ((instr & 0xf) == 0x2) {
      printf("MOV.L @R%u,R%u", m, n);
      return Ok;
    } else if ((instr & 0xf) == 0x3) {
      printf("MOV.L R%u,R%u", m, n);
      return Ok;
    } else if ((instr & 0xf) == 0x4) {
      printf("MOV.B @R%u+,R%u", m, n);
      return Ok;
    } else if ((instr & 0xf) == 0x5) {
      printf("MOV.W @R%u+,R%u", m, n);
      return Ok;
    } else if ((instr & 0xf) == 0x6) {
      printf("MOV.L @R%u+,R%u", m, n);
      return Ok;
    } else if ((instr & 0xf) == 0xc) {
      printf("EXTU.B R%u,R%u", m, n);
      return Ok;
    } else if ((instr & 0xf) == 0xd) {
      printf("EXTU.W R%u,R%u", m, n);
      return Ok;
    }
    break;
  }

  case 0x7: {
    int n = (instr >> 8) & 0xf;
    uint16_t imm = (instr & 0xff);
    printf("ADD #%d,R%u", imm, n);
    return Ok;
  }

  case 0x8: {
    if ((instr & 0x0f00) == 0x800) {
      uint16_t imm = instr & 0xff;
      printf("CMP/EQ #%u,R0", imm);
      return Ok;
    } else if ((instr & 0x0f00) == 0x900) {
      uint32_t disp = (int)(int8_t)(instr & 0xff) * 2;
      printf("BT PC+%08x", disp);
      return Ok;
    } else if ((instr & 0x0f00) == 0xb00) {
      uint32_t disp = (int)(int8_t)(instr & 0xff) * 2;
      printf("BF PC+%08x", disp);
      return Ok;
    } else {
      return Error;
    }
    break;
  }

  case 0x9: {
    int n = (instr >> 8) & 0xf;
    uint16_t disp = (instr & 0xff) * 2;
    printf("MOV.W @(%u,PC),R%u", disp, n);
    return Ok;
  }

  case 0xa: {
    uint32_t disp = instr & 0xfff;
    printf("BRA PC+%u", disp);
    return Ok;
  }

  case 0xb: {
    uint32_t disp = (instr & 0xfff) * 2;
    printf("BSR PC+%08x", disp);
    return Ok;
  }

  case 0xc:
    if ((instr & 0x0f00) == 0x0100) {
      uint16_t disp = (instr & 0xff) * 2;
      printf("MOV.W R0,@(%d,GBR)", disp);
      return Ok;
    } else if ((instr & 0x0f00) == 0x0700) {
      uint16_t disp = (instr & 0xff) * 4;
      printf("MOVA @(%d,PC),R0", disp);
      return Ok;
    }
    break;

  case 0xd: {
    int n = (instr >> 8) & 0xf;
    uint16_t disp = (instr & 0xff) * 4;
    printf("MOV.L @(%d,PC),R%u", disp, n);
    return Ok;
  }

  case 0xe: {
    int n = (instr >> 8) & 0xf;
    uint16_t imm = (instr & 0xff);
    printf("MOV #%d,R%u", (int)(int16_t)imm, n);
    return Ok;
  }

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
    printf("[%04x]: %04x ", address, instr);
    write_binary_u16(instr);
    printf(" ");
    if (decode(instr) == Error) {
      printf(".WORD %04x", instr);
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

  disassemble(&buffer, 512, 0x480);

  return 0;
}
