#include <assert.h>
#include <ctype.h>
#include <memory.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define USE_COLOR 1

#if USE_COLOR
#define COLOR(x) "\x1b[" x "m"
#else
#define COLOR(x)
#endif

#define SUCCESS(x) ((x) == OK)
#define PRINT_ERROR(...) fprintf(stderr, __VA_ARGS__)
#define CHECK_MSG(x, ...)                       \
  if (!(x)) {                                   \
    PRINT_ERROR("%s:%d: ", __FILE__, __LINE__); \
    PRINT_ERROR(__VA_ARGS__);                   \
    goto error;                                 \
  }
#define CHECK(x)  \
  do              \
    if (!(x)) {   \
      goto error; \
    }             \
  while (0)
#define ON_ERROR_RETURN \
  error:                \
  return ERROR
#define ON_ERROR_CLOSE_FILE_AND_RETURN \
  error:                               \
  if (file) {                          \
    fclose(file);                      \
  }                                    \
  return ERROR
#define UNREACHABLE(...) PRINT_ERROR(__VA_ARGS__), exit(1)

#define BLACK COLOR("30")
#define BLUE COLOR("34")
#define BOLD COLOR("1")
#define CYAN COLOR("36")
#define DEFAULT COLOR("0")
#define GREEN COLOR("32")
#define MAGENTA COLOR("35")
#define NO_BOLD COLOR("22")
#define RED COLOR("31")
#define WHITE COLOR("37")
#define YELLOW COLOR("33")

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef u32 Address;

typedef enum { OK, ERROR } Result;

typedef struct {
  u8* data;
  size_t size;
} Buffer;

#define SIGN_EXTEND(x, n) (u32)((s32)((x) << (32 - n)) >> (32 - n))

#define DISP "%d"
#define ADDR "0x%08x"
#define IMM "#%u"
#define SIMM "#%d"
#define REG "R%u"
#define REG_PAIR PAIR(REG, REG)
#define PAIR(x, y) x ", " y
#define AT(x) "@" x
#define AT_MINUS(x) AT("-" REG)
#define AT_PLUS(x) AT(REG "+")
#define AT2(x, y) "@(" x ", " y ")"

#define FOREACH_OP(V)                                                     \
  V(INVALID_OP, FORMAT_0, "INVALID", "")                                  \
  V(ADD_RM_RN, FORMAT_NM, "ADD", REG_PAIR)                                \
  V(ADD_I_RN, FORMAT_NI, "ADD", PAIR(IMM, REG))                           \
  V(ADDC_RM_RN, FORMAT_NM, "ADDC", REG_PAIR)                              \
  V(ADDV_RM_RN, FORMAT_NM, "ADDV", REG_PAIR)                              \
  V(AND_RM_RN, FORMAT_NM, "AND", REG_PAIR)                                \
  V(AND_I_R0, FORMAT_I, "AND", PAIR(IMM, "R0"))                           \
  V(ANDB_I_A_R0_GBR, FORMAT_I, "AND.B", PAIR(IMM, AT2("R0", "GBR")))      \
  V(BF, FORMAT_D, "BF", ADDR)                                             \
  V(BFS, FORMAT_D, "BF/S", ADDR)                                          \
  V(BRA, FORMAT_D12, "BRA", ADDR)                                         \
  V(BRAF_RM, FORMAT_M, "BRAF", REG)                                       \
  V(BSR, FORMAT_D12, "BSR", ADDR)                                         \
  V(BSRF_RM, FORMAT_M, "BSRF", REG)                                       \
  V(BT, FORMAT_D, "BT", ADDR)                                             \
  V(BTS, FORMAT_D, "BT/S", ADDR)                                          \
  V(CLRMAC, FORMAT_0, "CLRMAC", "")                                       \
  V(CLRT, FORMAT_0, "CLRT", "")                                           \
  V(CMPEQ_RM_RN, FORMAT_NM, "CMP/EQ", REG_PAIR)                           \
  V(CMPGE_RM_RN, FORMAT_NM, "CMP/GE", REG_PAIR)                           \
  V(CMPGT_RM_RN, FORMAT_NM, "CMP/GT", REG_PAIR)                           \
  V(CMPHI_RM_RN, FORMAT_NM, "CMP/HI", REG_PAIR)                           \
  V(CMPHS_RM_RN, FORMAT_NM, "CMP/HS", REG_PAIR)                           \
  V(CMPPL_RN, FORMAT_NM, "CMP/PL", REG)                                   \
  V(CMPPZ_RN, FORMAT_NM, "CMP/PZ", REG)                                   \
  V(CMPSTR_RM_RN, FORMAT_NM, "CMP/STR", REG_PAIR)                         \
  V(CMPEQ_I_R0, FORMAT_I, "CMP/EQ", PAIR(IMM, "R0"))                      \
  V(DIV0S_RM_RN, FORMAT_NM, "DIV0S", REG_PAIR)                            \
  V(DIV0U, FORMAT_0, "DIV0U", "")                                         \
  V(DIV1_RM_RN, FORMAT_NM, "DIV1", REG_PAIR)                              \
  V(DMULSL_RM_RN, FORMAT_NM, "DMULS.L", REG_PAIR)                         \
  V(DMULUL_RM_RN, FORMAT_NM, "DMULU.L", REG_PAIR)                         \
  V(DT_RN, FORMAT_N, "DT", REG)                                           \
  V(EXTSB_RM_RN, FORMAT_NM, "EXTS.B", REG_PAIR)                           \
  V(EXTSW_RM_RN, FORMAT_NM, "EXTS.W", REG_PAIR)                           \
  V(EXTUB_RM_RN, FORMAT_NM, "EXTU.B", REG_PAIR)                           \
  V(EXTUW_RM_RN, FORMAT_NM, "EXTU.W", REG_PAIR)                           \
  V(JMP_ARM, FORMAT_M, "JMP", AT(REG))                                    \
  V(JSR_ARM, FORMAT_M, "JSR", AT(REG))                                    \
  V(LDC_RM_SR, FORMAT_M, "LDC", PAIR(REG, "SR"))                          \
  V(LDC_RM_GBR, FORMAT_M, "LDC", PAIR(REG, "GBR"))                        \
  V(LDC_RM_VBR, FORMAT_M, "LDC", PAIR(REG, "VBR"))                        \
  V(LDCL_ARMP_SR, FORMAT_M, "LDC.L", PAIR(AT_PLUS(REG), "SR"))            \
  V(LDCL_ARMP_GBR, FORMAT_M, "LDC.L", PAIR(AT_PLUS(REG), "GBR"))          \
  V(LDCL_ARMP_VBR, FORMAT_M, "LDC.L", PAIR(AT_PLUS(REG), "VBR"))          \
  V(LDS_RM_MACH, FORMAT_M, "LDS", PAIR(REG, "MACH"))                      \
  V(LDS_RM_MACL, FORMAT_M, "LDS", PAIR(REG, "MACL"))                      \
  V(LDS_RM_PR, FORMAT_M, "LDS", PAIR(REG, "PR"))                          \
  V(LDSL_ARMP_MACH, FORMAT_M, "LDS.L", PAIR(AT_PLUS(REG), "MACH"))        \
  V(LDSL_ARMP_MACL, FORMAT_M, "LDS.L", PAIR(AT_PLUS(REG), "MACL"))        \
  V(LDSL_ARMP_PR, FORMAT_M, "LDS.L", PAIR(AT_PLUS(REG), "PR"))            \
  V(MACL_ARMP_ARNP, FORMAT_NM, "MAC.L", PAIR(AT_PLUS(REG), AT_PLUS(REG))) \
  V(MACW_ARMP_ARNP, FORMAT_NM, "MAC.W", PAIR(AT_PLUS(REG), AT_PLUS(REG))) \
  V(MOV_RM_RN, FORMAT_NM, "MOV", REG_PAIR)                                \
  V(MOVB_RM_ARN, FORMAT_NM, "MOV.B", PAIR(REG, AT(REG)))                  \
  V(MOVW_RM_ARN, FORMAT_NM, "MOV.W", PAIR(REG, AT(REG)))                  \
  V(MOVL_RM_ARN, FORMAT_NM, "MOV.L", PAIR(REG, AT(REG)))                  \
  V(MOVB_ARM_RN, FORMAT_NM, "MOV.B", PAIR(AT(REG), REG))                  \
  V(MOVW_ARM_RN, FORMAT_NM, "MOV.W", PAIR(AT(REG), REG))                  \
  V(MOVL_ARM_RN, FORMAT_NM, "MOV.L", PAIR(AT(REG), REG))                  \
  V(MOVB_RM_AMRN, FORMAT_NM, "MOV.B", PAIR(REG, AT_MINUS(REG)))           \
  V(MOVW_RM_AMRN, FORMAT_NM, "MOV.W", PAIR(REG, AT_MINUS(REG)))           \
  V(MOVL_RM_AMRN, FORMAT_NM, "MOV.L", PAIR(REG, AT_MINUS(REG)))           \
  V(MOVB_ARMP_RN, FORMAT_NM, "MOV.B", PAIR(AT_PLUS(REG), REG))            \
  V(MOVW_ARMP_RN, FORMAT_NM, "MOV.W", PAIR(AT_PLUS(REG), REG))            \
  V(MOVL_ARMP_RN, FORMAT_NM, "MOV.L", PAIR(AT_PLUS(REG), REG))            \
  V(MOVB_RM_A_R0_RN, FORMAT_NM, "MOV.B", PAIR(REG, AT2("R0", REG)))       \
  V(MOVW_RM_A_R0_RN, FORMAT_NM, "MOV.W", PAIR(REG, AT2("R0", REG)))       \
  V(MOVL_RM_A_R0_RN, FORMAT_NM, "MOV.L", PAIR(REG, AT2("R0", REG)))       \
  V(MOVB_A_R0_RM_RN, FORMAT_NM, "MOV.B", PAIR(AT2("R0", REG), REG))       \
  V(MOVW_A_R0_RM_RN, FORMAT_NM, "MOV.W", PAIR(AT2("R0", REG), REG))       \
  V(MOVL_A_R0_RM_RN, FORMAT_NM, "MOV.L", PAIR(AT2("R0", REG), REG))       \
  V(MOV_I_RN, FORMAT_NI, "MOV", PAIR(SIMM, REG))                          \
  V(MOVW_A_D_PC_RN, FORMAT_ND8, "MOV.W", PAIR(AT(ADDR), REG))             \
  V(MOVL_A_D_PC_RN, FORMAT_ND8, "MOV.L", PAIR(AT(ADDR), REG))             \
  V(MOVB_A_D_GBR_R0, FORMAT_D, "MOV.B", PAIR(AT2(DISP, "GBR"), "R0"))     \
  V(MOVW_A_D_GBR_R0, FORMAT_D, "MOV.W", PAIR(AT2(DISP, "GBR"), "R0"))     \
  V(MOVL_A_D_GBR_R0, FORMAT_D, "MOV.L", PAIR(AT2(DISP, "GBR"), "R0"))     \
  V(MOVB_R0_A_D_GBR, FORMAT_D, "MOV.B", PAIR("R0", AT2(DISP, "GBR")))     \
  V(MOVW_R0_A_D_GBR, FORMAT_D, "MOV.W", PAIR("R0", AT2(DISP, "GBR")))     \
  V(MOVL_R0_A_D_GBR, FORMAT_D, "MOV.L", PAIR("R0", AT2(DISP, "GBR")))     \
  V(MOVB_R0_A_D_RN, FORMAT_ND4, "MOV.B", PAIR("R0", AT2(DISP, REG)))      \
  V(MOVW_R0_A_D_RN, FORMAT_ND4, "MOV.W", PAIR("R0", AT2(DISP, REG)))      \
  V(MOVL_RM_A_D_RN, FORMAT_NMD, "MOV.L", PAIR(REG, AT2(DISP, REG)))       \
  V(MOVB_A_D_RM_R0, FORMAT_MD, "MOV.B", PAIR(AT2(DISP, REG), "R0"))       \
  V(MOVW_A_D_RM_R0, FORMAT_MD, "MOV.W", PAIR(AT2(DISP, REG), "R0"))       \
  V(MOVL_A_D_RM_RN, FORMAT_NMD, "MOV.L", PAIR(AT2(REG, DISP), REG))       \
  V(MOVA_A_D_PC_R0, FORMAT_D, "MOV", PAIR(ADDR, "R0"))                    \
  V(MOVT_RN, FORMAT_N, "MOVT", REG)                                       \
  V(MULL_RM_RN, FORMAT_NM, "MUL.L", REG_PAIR)                             \
  V(MULSW_RM_RN, FORMAT_NM, "MULS.W", REG_PAIR)                           \
  V(MULUW_RM_RN, FORMAT_NM, "MULU.W", REG_PAIR)                           \
  V(NEGC_RM_RN, FORMAT_NM, "NEGC", REG_PAIR)                              \
  V(NEG_RM_RN, FORMAT_NM, "NEG", REG_PAIR)                                \
  V(NOP, FORMAT_0, "NOP", "")                                             \
  V(NOT_RM_RN, FORMAT_NM, "NOT", REG_PAIR)                                \
  V(OR_RM_RN, FORMAT_NM, "OR", REG_PAIR)                                  \
  V(OR_I_R0, FORMAT_I, "OR", PAIR(IMM, "R0"))                             \
  V(ORB_I_A_R0_GBR, FORMAT_I, "OR.B", PAIR(IMM, AT2("R0", "GBR")))        \
  V(ROTCL_RN, FORMAT_N, "ROTCL", REG)                                     \
  V(ROTCR_RN, FORMAT_N, "ROTCR", REG)                                     \
  V(ROTL_RN, FORMAT_N, "ROTL", REG)                                       \
  V(ROTR_RN, FORMAT_N, "ROTR", REG)                                       \
  V(RTE, FORMAT_0, "RTE", "")                                             \
  V(RTS, FORMAT_0, "RTS", "")                                             \
  V(SETT, FORMAT_0, "SETT", "")                                           \
  V(SHAL_RN, FORMAT_N, "SHAL", REG)                                       \
  V(SHAR_RN, FORMAT_N, "SHAR", REG)                                       \
  V(SHLL_RN, FORMAT_N, "SHLL", REG)                                       \
  V(SHLL2_RN, FORMAT_N, "SHLL2", REG)                                     \
  V(SHLL8_RN, FORMAT_N, "SHLL8", REG)                                     \
  V(SHLL16_RN, FORMAT_N, "SHLL16", REG)                                   \
  V(SHLR_RN, FORMAT_N, "SHLR", REG)                                       \
  V(SHLR2_RN, FORMAT_N, "SHLR2", REG)                                     \
  V(SHLR8_RN, FORMAT_N, "SHLR8", REG)                                     \
  V(SHLR16_RN, FORMAT_N, "SHLR16", REG)                                   \
  V(SLEEP, FORMAT_0, "SLEEP", "")                                         \
  V(STC_SR_RN, FORMAT_N, "STC", PAIR("SR", REG))                          \
  V(STC_GBR_RN, FORMAT_N, "STC", PAIR("GBR", REG))                        \
  V(STC_VBR_RN, FORMAT_N, "STC", PAIR("VBR", REG))                        \
  V(STCL_SR_AMRN, FORMAT_N, "STC.L", PAIR("SR", AT_MINUS(REG)))           \
  V(STCL_GBR_AMRN, FORMAT_N, "STC.L", PAIR("GBR", AT_MINUS(REG)))         \
  V(STCL_VBR_AMRN, FORMAT_N, "STC.L", PAIR("VBR", AT_MINUS(REG)))         \
  V(STS_MACH_RN, FORMAT_N, "STS", PAIR("MACH", REG))                      \
  V(STS_MACL_RN, FORMAT_N, "STS", PAIR("MACL", REG))                      \
  V(STS_PR_RN, FORMAT_N, "STS", PAIR("PR", REG))                          \
  V(STSL_MACH_AMRN, FORMAT_N, "STS.L", PAIR("MACH", AT_MINUS(REG)))       \
  V(STSL_MACL_AMRN, FORMAT_N, "STS.L", PAIR("MACL", AT_MINUS(REG)))       \
  V(STSL_PR_AMRN, FORMAT_N, "STS.L", PAIR("PR", AT_MINUS(REG)))           \
  V(SUB_RM_RN, FORMAT_NM, "SUB", REG_PAIR)                                \
  V(SUBC_RM_RN, FORMAT_NM, "SUBC", REG_PAIR)                              \
  V(SUBV_RM_RN, FORMAT_NM, "SUBV", REG_PAIR)                              \
  V(SWAPB_RM_RN, FORMAT_NM, "SWAP.B", REG_PAIR)                           \
  V(SWAPW_RM_RN, FORMAT_NM, "SWAP.W", REG_PAIR)                           \
  V(TASB_ARN, FORMAT_N, "TAS.B", AT(REG))                                 \
  V(TRAPA_I, FORMAT_I, "TRAPA", IMM)                                      \
  V(TST_RM_RN, FORMAT_NM, "TST", REG_PAIR)                                \
  V(TST_I_R0, FORMAT_I, "TST", PAIR(IMM, "R0"))                           \
  V(TSTB_I_A_R0_GBR, FORMAT_I, "TST.B", PAIR(IMM, AT2("R0", "GBR")))      \
  V(XOR_RM_RN, FORMAT_NM, "XOR", REG_PAIR)                                \
  V(XOR_I_R0, FORMAT_I, "XOR", PAIR(IMM, "R0"))                           \
  V(XORB_I_A_R0_GBR, FORMAT_I, "XOR.B", PAIR(IMM, AT2("R0", "GBR")))      \
  V(XTRCT_RM_RN, FORMAT_NM, "XTRCT", REG_PAIR)

typedef enum {
#define V(name, format, op_str, fmt_str) name,
  FOREACH_OP(V)
#undef V
} Op;

typedef enum {
  FORMAT_0,
  FORMAT_M,
  FORMAT_N,
  FORMAT_NM,
  FORMAT_MD,
  FORMAT_ND4,
  FORMAT_NMD,
  FORMAT_D,
  FORMAT_D12,
  FORMAT_ND8,
  FORMAT_I,
  FORMAT_NI,
} InstrFormat;

typedef enum {
  MEMORY_MAP_INVALID,
  MEMORY_MAP_ROM,
} MemoryMapType;

typedef struct {
  MemoryMapType type;
  Address addr;
} MemoryTypeAddressPair;

typedef struct {
  InstrFormat format;
  const char* op_str;
  const char* fmt_str;
} OpInfo;

typedef struct {
  Op op;
  u8 n, m;
  u8 pad;
  union { u32 d, i; };
} Instr;

typedef struct {
} State;

typedef struct {
  State state;
  Buffer rom;
} Emulator;

OpInfo s_op_info[] = {
#define V(name, format, op_str, fmt_str) {format, op_str, fmt_str},
    FOREACH_OP(V)
#undef V
};

MemoryTypeAddressPair map_address(Emulator* e, Address address) {
  switch ((address >> 28) & 0xf) {
    case 0xe:
      if (address < 0xe0000000 + e->rom.size) {
        return (MemoryTypeAddressPair){.type = MEMORY_MAP_ROM,
                                       .addr = address - 0xe0000000};
      }
      /* Fallthrough. */

    default:
      return (MemoryTypeAddressPair){.type = MEMORY_MAP_INVALID};
  }
}

u16 read_u16(Emulator* e, Address address) {
  MemoryTypeAddressPair pair = map_address(e, address);
  switch (pair.type) {
    case MEMORY_MAP_ROM:
      /* TODO(binji): assumes little-endian. */
      return ((u16*)e->rom.data)[pair.addr >> 1];

    default:
    case MEMORY_MAP_INVALID:
      return 0xffff;
  }
}

u8 read_u8(Emulator* e, Address address) {
  u16 x = read_u16(e, address & ~1);
  return address & 1 ? x >> 8 : x & 0xff;
}

u32 read_u32(Emulator* e, Address address) {
  return (read_u16(e, address) << 16) | read_u16(e, address + 2);
}

Result read_file(const char* filename, Buffer* buffer) {
  FILE* file = fopen(filename, "rb");
  CHECK_MSG(file, "unable to open file \"%s\".\n", filename);

  fseek(file, 0, SEEK_END);
  size_t size = ftell(file);
  fseek(file, 0, SEEK_SET);

  u8* data = malloc(size);
  CHECK_MSG(fread(data, size, 1, file) == 1, "fread failed.\n");
  fclose(file);
  buffer->data = data;
  buffer->size = size;

  return OK;
  ON_ERROR_CLOSE_FILE_AND_RETURN;
}

void print_instr(Emulator* e, Instr instr) {
  OpInfo op_info = s_op_info[instr.op];
  printf(GREEN "%s" WHITE " ", op_info.op_str);

  // clang-format off
  switch (op_info.format) {
    case FORMAT_0: break;
    case FORMAT_M: printf(op_info.fmt_str, instr.m); break;
    case FORMAT_N: printf(op_info.fmt_str, instr.n); break;
    case FORMAT_NM: printf(op_info.fmt_str, instr.m, instr.n); break;
    case FORMAT_MD: printf(op_info.fmt_str, instr.d, instr.m); break;
    case FORMAT_NMD: printf(op_info.fmt_str, instr.m, instr.d, instr.n); break;
    case FORMAT_D:
    case FORMAT_D12: printf(op_info.fmt_str, instr.d); break;
    case FORMAT_ND4:
    case FORMAT_ND8: printf(op_info.fmt_str, instr.d, instr.n); break;
    case FORMAT_I: printf(op_info.fmt_str, instr.i); break;
    case FORMAT_NI: printf(op_info.fmt_str, instr.i, instr.n); break;
  }
  // clang-format on

  if ((op_info.format == FORMAT_D && instr.op == MOVA_A_D_PC_R0) ||
      (op_info.format == FORMAT_ND8)) {
    /* PC relative memory access */
    u32 val;
    if (instr.op == MOVW_A_D_PC_RN) {
      val = SIGN_EXTEND(read_u16(e, instr.d), 16);
    } else {
      val = read_u32(e, instr.d);
    }
    printf("  ; 0x%08x", val);
  }
}

Instr format_0(Op op) { return (Instr){.op = op}; }

Instr format_n(u16 code, Op op) {
  return (Instr){.op = op, .n = (code >> 8) & 0xf};
}

Instr format_m(u16 code, Op op) {
  return (Instr){.op = op, .m = (code >> 8) & 0xf};
}

Instr format_nm(u16 code, Op op) {
  return (Instr){.op = op, .n = (code >> 8) & 0xf, .m = (code >> 4) & 0xf};
}

Instr format_nmd(u16 code, Op op, int mul) {
  return (Instr){.op = op,
                 .n = (code >> 8) & 0xf,
                 .m = (code >> 4) & 0xf,
                 .d = (code & 0xf) * mul};
}

Instr format_nui(u16 code, Op op) {
  return (Instr){.op = op, .n = (code >> 8) & 0xf, .i = (code & 0xff)};
}

Instr format_nsi(u16 code, Op op) {
  return (Instr){
      .op = op,
      .n = (code >> 8) & 0xf,
      .i = SIGN_EXTEND(code & 0xff, 8),
  };
}

Instr format_md(u16 code, Op op, int mul) {
  return (Instr){.op = op, .m = (code >> 4) & 0xf, .d = (code & 0xf) * mul};
}

Instr format_nd4(u16 code, Op op, int mul) {
  return (Instr){.op = op, .n = (code >> 4) & 0xf, .d = (code & 0xf) * mul};
}

Instr format_nd8(u16 code, Op op, u32 pc, int mul) {
  u32 disp = (code & 0xff) * mul;
  u32 d = (mul == 4 ? (pc & ~3) : pc) + 4 + disp;
  return (Instr){.op = op, .n = (code >> 8) & 0xf, .d = d};
}

Instr format_i(u16 code, Op op) { return (Instr){.op = op, .i = code & 0xff}; }

Instr format_sd(u16 code, Op op, u32 pc) {
  u32 disp = SIGN_EXTEND(code & 0xff, 8) * 2;
  return (Instr){.op = op, .d = pc + 4 + disp};
}

Instr format_ud(u16 code, Op op, int mul) {
  return (Instr){.op = op, .d = (code & 0xff) * mul};
}

Instr format_mova(u16 code, Op op, u32 pc, int mul) {
  u32 disp = (code & 0xff) * mul;
  return (Instr){.op = op, .d = pc + 4 + disp};
}

Instr format_d12(u16 code, Op op, u32 pc) {
  u32 disp = SIGN_EXTEND(code & 0xfff, 12) * 2;
  return (Instr){.op = op, .d = pc + 4 + disp};
}

Instr decode(u32 pc, u16 code) {
  switch (code >> 12) {
    case 0x0:
      // clang-format off
    switch (code & 0xf) {
      case 0x2:
        switch (code & 0xf0) {
          case 0x00: return format_n(code, STC_SR_RN);
          case 0x10: return format_n(code, STC_GBR_RN);
          case 0x20: return format_n(code, STC_VBR_RN);
        }
        break;
      case 0x3:
        switch (code & 0xf0) {
          case 0x00: return format_nm(code, BSRF_RM);
          case 0x20: return format_nm(code, BRAF_RM);
        }
        break;
      case 0x4: return format_nm(code, MOVB_RM_A_R0_RN);
      case 0x5: return format_nm(code, MOVW_RM_A_R0_RN);
      case 0x6: return format_nm(code, MOVL_RM_A_R0_RN);
      case 0x7: return format_nm(code, MULL_RM_RN);
      case 0x8:
        switch (code) {
          case 0x08: return format_0(CLRT);
          case 0x18: return format_0(SETT);
          case 0x28: return format_0(CLRMAC);
        }
        break;
      case 0x9:
        switch (code & 0xf0) {
          case 0x00: return format_0(NOP);
          case 0x10: return format_0(DIV0U);
          case 0x20: return format_n(code, MOVT_RN);
        }
        break;
      case 0xa:
        switch (code & 0xf0) {
          case 0x00: return format_n(code, STS_MACH_RN);
          case 0x10: return format_n(code, STS_MACL_RN);
          case 0x20: return format_n(code, STS_PR_RN);
        }
        break;
      case 0xb: // RTS SLEEP RTE
        switch (code & 0xf0) {
          case 0x00: return format_0(RTS);
          case 0x10: return format_0(SLEEP);
          case 0x20: return format_0(RTE);
        }
        break;
      case 0xc: return format_nm(code, MOVB_A_R0_RM_RN);
      case 0xd: return format_nm(code, MOVW_A_R0_RM_RN);
      case 0xe: return format_nm(code, MOVL_A_R0_RM_RN);
      case 0xf: return format_nm(code, MACL_ARMP_ARNP);
    }
      // clang-format on
      goto invalid;

    case 0x1:
      return format_nmd(code, MOVL_RM_A_D_RN, 4);

    case 0x2:
      // clang-format off
    switch (code & 0xf) {
      case 0x0: return format_nm(code, MOVB_RM_ARN);
      case 0x1: return format_nm(code, MOVW_RM_ARN);
      case 0x2: return format_nm(code, MOVL_RM_ARN);
      case 0x4: return format_nm(code, MOVB_RM_AMRN);
      case 0x5: return format_nm(code, MOVW_RM_AMRN);
      case 0x6: return format_nm(code, MOVL_RM_AMRN);
      case 0x7: return format_nm(code, DIV0S_RM_RN);
      case 0x8: return format_nm(code, TST_RM_RN);
      case 0x9: return format_nm(code, AND_RM_RN);
      case 0xa: return format_nm(code, XOR_RM_RN);
      case 0xb: return format_nm(code, OR_RM_RN);
      case 0xc: return format_nm(code, CMPSTR_RM_RN);
      case 0xd: return format_nm(code, XTRCT_RM_RN);
      case 0xe: return format_nm(code, MULUW_RM_RN);
      case 0xf: return format_nm(code, MULSW_RM_RN);
    }
      // clang-format on
      goto invalid;

    case 0x3:
      // clang-format off
    switch (code & 0xf) {
      case 0x0: return format_nm(code, CMPEQ_RM_RN);
      case 0x2: return format_nm(code, CMPHS_RM_RN);
      case 0x3: return format_nm(code, CMPGE_RM_RN);
      case 0x4: return format_nm(code, DIV1_RM_RN);
      case 0x5: return format_nm(code, DMULUL_RM_RN);
      case 0x6: return format_nm(code, CMPHI_RM_RN);
      case 0x7: return format_nm(code, CMPGT_RM_RN);
      case 0x8: return format_nm(code, SUB_RM_RN);
      case 0xa: return format_nm(code, SUBC_RM_RN);
      case 0xb: return format_nm(code, SUBV_RM_RN);
      case 0xc: return format_nm(code, ADD_RM_RN);
      case 0xd: return format_nm(code, DMULSL_RM_RN);
      case 0xe: return format_nm(code, ADDC_RM_RN);
      case 0xf: return format_nm(code, ADDV_RM_RN);
    }
      // clang-format on
      goto invalid;

    case 0x4:
      // clang-format off
    switch (code & 0xff) {
      case 0x00: return format_n(code, SHLL_RN);
      case 0x01: return format_n(code, SHLR_RN);
      case 0x02: return format_n(code, STSL_MACH_AMRN);
      case 0x03: return format_n(code, STCL_SR_AMRN);
      case 0x04: return format_n(code, ROTL_RN);
      case 0x05: return format_n(code, ROTR_RN);
      case 0x06: return format_m(code, LDSL_ARMP_MACH);
      case 0x07: return format_m(code, LDSL_ARMP_PR);
      case 0x08: return format_n(code, SHLL2_RN);
      case 0x09: return format_n(code, SHLR2_RN);
      case 0x0a: return format_m(code, LDS_RM_MACH);
      case 0x0b: return format_m(code, JSR_ARM);
      case 0x0e: return format_m(code, LDC_RM_SR);
      case 0x10: return format_n(code, DT_RN);
      case 0x11: return format_n(code, CMPPZ_RN);
      case 0x12: return format_n(code, STSL_MACL_AMRN);
      case 0x13: return format_n(code, STCL_GBR_AMRN);
      case 0x15: return format_n(code, CMPPL_RN);
      case 0x16: return format_m(code, LDSL_ARMP_MACL);
      case 0x17: return format_m(code, LDCL_ARMP_GBR);
      case 0x18: return format_n(code, SHLL8_RN);
      case 0x19: return format_n(code, SHLR8_RN);
      case 0x1a: return format_m(code, LDS_RM_MACL);
      case 0x1b: return format_n(code, TASB_ARN);
      case 0x1e: return format_m(code, LDC_RM_GBR);
      case 0x20: return format_n(code, SHAL_RN);
      case 0x21: return format_n(code, SHAR_RN);
      case 0x22: return format_n(code, STSL_PR_AMRN);
      case 0x23: return format_n(code, STCL_VBR_AMRN);
      case 0x24: return format_n(code, ROTCL_RN);
      case 0x25: return format_n(code, ROTCR_RN);
      case 0x26: return format_m(code, LDSL_ARMP_PR);
      case 0x27: return format_m(code, LDCL_ARMP_VBR);
      case 0x28: return format_n(code, SHLL16_RN);
      case 0x29: return format_n(code, SHLR16_RN);
      case 0x2a: return format_m(code, LDS_RM_PR);
      case 0x2b: return format_m(code, JMP_ARM);
      case 0x2e: return format_m(code, LDC_RM_VBR);

      case 0x0f: case 0x1f: case 0x2f: case 0x3f:
      case 0x4f: case 0x5f: case 0x6f: case 0x7f:
      case 0x8f: case 0x9f: case 0xaf: case 0xbf:
      case 0xcf: case 0xdf: case 0xef: case 0xff:
        return format_nm(code, MACW_ARMP_ARNP);
    }
      // clang-format on
      goto invalid;

    case 0x5:
      return format_nmd(code, MOVL_A_D_RM_RN, 4);

    case 0x6:
      // clang-format off
    switch (code & 0xf) {
      case 0x0: return format_nm(code, MOVB_ARM_RN);
      case 0x1: return format_nm(code, MOVW_ARM_RN);
      case 0x2: return format_nm(code, MOVL_ARM_RN);
      case 0x3: return format_nm(code, MOV_RM_RN);
      case 0x4: return format_nm(code, MOVB_ARMP_RN);
      case 0x5: return format_nm(code, MOVW_ARMP_RN);
      case 0x6: return format_nm(code, MOVL_ARMP_RN);
      case 0x7: return format_nm(code, NOT_RM_RN);
      case 0x8: return format_nm(code, SWAPB_RM_RN);
      case 0x9: return format_nm(code, SWAPW_RM_RN);
      case 0xa: return format_nm(code, NEGC_RM_RN);
      case 0xb: return format_nm(code, NEG_RM_RN);
      case 0xc: return format_nm(code, EXTUB_RM_RN);
      case 0xd: return format_nm(code, EXTUW_RM_RN);
      case 0xe: return format_nm(code, EXTSB_RM_RN);
      case 0xf: return format_nm(code, EXTSW_RM_RN);
    }
      // clang-format on
      goto invalid;

    case 0x7:
      return format_nui(code, ADD_I_RN);

    case 0x8:
      // clang-format off
    switch (code & 0x0f00) {
      case 0x000: return format_nd4(code, MOVB_R0_A_D_RN, 1);
      case 0x100: return format_nd4(code, MOVW_R0_A_D_RN, 2);
      case 0x400: return format_md(code, MOVB_A_D_RM_R0, 1);
      case 0x500: return format_md(code, MOVW_A_D_RM_R0, 2);
      case 0x800: return format_i(code, CMPEQ_I_R0);
      case 0x900: return format_sd(code, BT, pc);
      case 0xb00: return format_sd(code, BF, pc);
      case 0xd00: return format_sd(code, BTS, pc);
      case 0xf00: return format_sd(code, BFS, pc);
    }
      // clang-format on
      goto invalid;

    case 0x9:
      return format_nd8(code, MOVW_A_D_PC_RN, pc, 2);

    case 0xa:
      return format_d12(code, BRA, pc);

    case 0xb:
      return format_d12(code, BSR, pc);

    case 0xc:
      // clang-format off
    switch (code & 0x0f00) {
      case 0x0000: return format_ud(code, MOVB_R0_A_D_GBR, 1);
      case 0x0100: return format_ud(code, MOVW_R0_A_D_GBR, 2);
      case 0x0200: return format_ud(code, MOVL_R0_A_D_GBR, 4);
      case 0x0300: return format_i(code, TRAPA_I);
      case 0x0400: return format_ud(code, MOVB_A_D_GBR_R0, 1);
      case 0x0500: return format_ud(code, MOVW_A_D_GBR_R0, 2);
      case 0x0600: return format_ud(code, MOVL_A_D_GBR_R0, 4);
      case 0x0700: return format_mova(code, MOVA_A_D_PC_R0, pc, 4);
      case 0x0800: return format_i(code, TST_I_R0);
      case 0x0900: return format_i(code, AND_I_R0);
      case 0x0a00: return format_i(code, XOR_I_R0);
      case 0x0b00: return format_i(code, OR_I_R0);
      case 0x0c00: return format_i(code, TSTB_I_A_R0_GBR);
      case 0x0d00: return format_i(code, ANDB_I_A_R0_GBR);
      case 0x0e00: return format_i(code, XORB_I_A_R0_GBR);
      case 0x0f00: return format_i(code, ORB_I_A_R0_GBR);
    }
      // clang-format on
      goto invalid;

    case 0xd:
      return format_nd8(code, MOVL_A_D_PC_RN, pc, 4);

    case 0xe:
      return format_nsi(code, MOV_I_RN);

    case 0xf: {
      goto invalid;
    }
  }

  assert(0);
invalid:
  return format_0(INVALID_OP);
}

void disassemble(Emulator* e, size_t num_instrs, u32 address) {
  size_t i;
  for (i = 0; i < num_instrs; ++i, address += 2) {
    u32 pc = 0xe0000000 + address;
    u16 code = read_u16(e, pc);
    printf(YELLOW "[%08x]: " WHITE "%04x ", pc, code);
    Instr instr = decode(pc, code);
    if (instr.op == INVALID_OP) {
      printf(MAGENTA ".WORD %04x" WHITE, code);
    } else {
      print_instr(e, instr);
    }

    printf("\n");
  }
}

int main(int argc, char** argv) {
  --argc; ++argv;
  int result = 1;
  CHECK_MSG(argc == 1, "no rom file given.\n");
  const char* rom_filename = argv[0];

  Buffer buffer;
  CHECK(SUCCESS(read_file(rom_filename, &buffer)));
  Emulator e = {.rom = buffer};

  disassemble(&e, 1024 * 1024, 0);

  return 0;
  ON_ERROR_RETURN;
}
