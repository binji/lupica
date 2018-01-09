#include <assert.h>
#include <ctype.h>
#include <memory.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define USE_COLOR 1

#if USE_COLOR
#define COLOR(x) "\x1b[" x "m"
#else
#define COLOR(x)
#endif

#define ZERO_MEMORY(x) memset(&(x), 0, sizeof(x))

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

#define MAKE_BOLD(x) BOLD x NO_BOLD
#define DISP "%d"
#define ADDR "0x%08x"
#define IMM "#%u"
#define SIMM "#%d"
#define REG MAKE_BOLD("r%u")
#define REG0 MAKE_BOLD("r0")
#define GBR MAKE_BOLD("gbr")
#define VBR MAKE_BOLD("vbr")
#define MACH MAKE_BOLD("mach")
#define MACL MAKE_BOLD("macl")
#define SR MAKE_BOLD("sr")
#define PR MAKE_BOLD("pr")
#define REG_PAIR PAIR(REG, REG)
#define PAIR(x, y) x ", " y
#define AT(x) "@" x
#define AT_MINUS(x) AT("-" REG)
#define AT_PLUS(x) AT(REG "+")
#define AT2(x, y) "@(" x ", " y ")"

#define FOREACH_REGISTER(V) \
  V(r0)                     \
  V(r1)                     \
  V(r2)                     \
  V(r3)                     \
  V(r4)                     \
  V(r5)                     \
  V(r6)                     \
  V(r7)                     \
  V(r8)                     \
  V(r9)                     \
  V(r10)                    \
  V(r11)                    \
  V(r12)                    \
  V(r13)                    \
  V(r14)                    \
  V(r15)                    \
  V(gbr)                    \
  V(vbr)                    \
  V(mach)                   \
  V(macl)                   \
  V(pr)                     \
  V(sr)

#define FOREACH_OP(V)                                                     \
  V(INVALID_OP, FORMAT_0, "invalid", "")                                  \
  V(ADD_RM_RN, FORMAT_NM, "add", REG_PAIR)                                \
  V(ADD_I_RN, FORMAT_NI, "add", PAIR(SIMM, REG))                          \
  V(ADDC_RM_RN, FORMAT_NM, "addc", REG_PAIR)                              \
  V(ADDV_RM_RN, FORMAT_NM, "addv", REG_PAIR)                              \
  V(AND_RM_RN, FORMAT_NM, "and", REG_PAIR)                                \
  V(AND_I_R0, FORMAT_I, "and", PAIR(IMM, REG0))                           \
  V(ANDB_I_A_R0_GBR, FORMAT_I, "and.b", PAIR(IMM, AT2(REG0, GBR)))        \
  V(BF, FORMAT_D, "bf", ADDR)                                             \
  V(BFS, FORMAT_D, "bf/s", ADDR)                                          \
  V(BRA, FORMAT_D12, "bra", ADDR)                                         \
  V(BRAF_RM, FORMAT_M, "braf", REG)                                       \
  V(BSR, FORMAT_D12, "bsr", ADDR)                                         \
  V(BSRF_RM, FORMAT_M, "bsrf", REG)                                       \
  V(BT, FORMAT_D, "bt", ADDR)                                             \
  V(BTS, FORMAT_D, "bt/s", ADDR)                                          \
  V(CLRMAC, FORMAT_0, "clrmac", "")                                       \
  V(CLRT, FORMAT_0, "clrt", "")                                           \
  V(CMPEQ_RM_RN, FORMAT_NM, "cmp/eq", REG_PAIR)                           \
  V(CMPGE_RM_RN, FORMAT_NM, "cmp/ge", REG_PAIR)                           \
  V(CMPGT_RM_RN, FORMAT_NM, "cmp/gt", REG_PAIR)                           \
  V(CMPHI_RM_RN, FORMAT_NM, "cmp/hi", REG_PAIR)                           \
  V(CMPHS_RM_RN, FORMAT_NM, "cmp/hs", REG_PAIR)                           \
  V(CMPPL_RN, FORMAT_NM, "cmp/pl", REG)                                   \
  V(CMPPZ_RN, FORMAT_NM, "cmp/pz", REG)                                   \
  V(CMPSTR_RM_RN, FORMAT_NM, "cmp/str", REG_PAIR)                         \
  V(CMPEQ_I_R0, FORMAT_I, "cmp/eq", PAIR(SIMM, REG0))                     \
  V(DIV0S_RM_RN, FORMAT_NM, "div0s", REG_PAIR)                            \
  V(DIV0U, FORMAT_0, "div0u", "")                                         \
  V(DIV1_RM_RN, FORMAT_NM, "div1", REG_PAIR)                              \
  V(DMULSL_RM_RN, FORMAT_NM, "dmuls.l", REG_PAIR)                         \
  V(DMULUL_RM_RN, FORMAT_NM, "dmulu.l", REG_PAIR)                         \
  V(DT_RN, FORMAT_N, "dt", REG)                                           \
  V(EXTSB_RM_RN, FORMAT_NM, "exts.b", REG_PAIR)                           \
  V(EXTSW_RM_RN, FORMAT_NM, "exts.w", REG_PAIR)                           \
  V(EXTUB_RM_RN, FORMAT_NM, "extu.b", REG_PAIR)                           \
  V(EXTUW_RM_RN, FORMAT_NM, "extu.w", REG_PAIR)                           \
  V(JMP_ARM, FORMAT_M, "jmp", AT(REG))                                    \
  V(JSR_ARM, FORMAT_M, "jsr", AT(REG))                                    \
  V(LDC_RM_SR, FORMAT_M, "ldc", PAIR(REG, SR))                            \
  V(LDC_RM_GBR, FORMAT_M, "ldc", PAIR(REG, GBR))                          \
  V(LDC_RM_VBR, FORMAT_M, "ldc", PAIR(REG, VBR))                          \
  V(LDCL_ARMP_SR, FORMAT_M, "ldc.l", PAIR(AT_PLUS(REG), SR))              \
  V(LDCL_ARMP_GBR, FORMAT_M, "ldc.l", PAIR(AT_PLUS(REG), GBR))            \
  V(LDCL_ARMP_VBR, FORMAT_M, "ldc.l", PAIR(AT_PLUS(REG), VBR))            \
  V(LDS_RM_MACH, FORMAT_M, "lds", PAIR(REG, MACH))                        \
  V(LDS_RM_MACL, FORMAT_M, "lds", PAIR(REG, MACL))                        \
  V(LDS_RM_PR, FORMAT_M, "lds", PAIR(REG, PR))                            \
  V(LDSL_ARMP_MACH, FORMAT_M, "lds.l", PAIR(AT_PLUS(REG), MACH))          \
  V(LDSL_ARMP_MACL, FORMAT_M, "lds.l", PAIR(AT_PLUS(REG), MACL))          \
  V(LDSL_ARMP_PR, FORMAT_M, "lds.l", PAIR(AT_PLUS(REG), PR))              \
  V(MACL_ARMP_ARNP, FORMAT_NM, "mac.l", PAIR(AT_PLUS(REG), AT_PLUS(REG))) \
  V(MACW_ARMP_ARNP, FORMAT_NM, "mac.w", PAIR(AT_PLUS(REG), AT_PLUS(REG))) \
  V(MOV_RM_RN, FORMAT_NM, "mov", REG_PAIR)                                \
  V(MOVB_RM_ARN, FORMAT_NM, "mov.b", PAIR(REG, AT(REG)))                  \
  V(MOVW_RM_ARN, FORMAT_NM, "mov.w", PAIR(REG, AT(REG)))                  \
  V(MOVL_RM_ARN, FORMAT_NM, "mov.l", PAIR(REG, AT(REG)))                  \
  V(MOVB_ARM_RN, FORMAT_NM, "mov.b", PAIR(AT(REG), REG))                  \
  V(MOVW_ARM_RN, FORMAT_NM, "mov.w", PAIR(AT(REG), REG))                  \
  V(MOVL_ARM_RN, FORMAT_NM, "mov.l", PAIR(AT(REG), REG))                  \
  V(MOVB_RM_AMRN, FORMAT_NM, "mov.b", PAIR(REG, AT_MINUS(REG)))           \
  V(MOVW_RM_AMRN, FORMAT_NM, "mov.w", PAIR(REG, AT_MINUS(REG)))           \
  V(MOVL_RM_AMRN, FORMAT_NM, "mov.l", PAIR(REG, AT_MINUS(REG)))           \
  V(MOVB_ARMP_RN, FORMAT_NM, "mov.b", PAIR(AT_PLUS(REG), REG))            \
  V(MOVW_ARMP_RN, FORMAT_NM, "mov.w", PAIR(AT_PLUS(REG), REG))            \
  V(MOVL_ARMP_RN, FORMAT_NM, "mov.l", PAIR(AT_PLUS(REG), REG))            \
  V(MOVB_RM_A_R0_RN, FORMAT_NM, "mov.b", PAIR(REG, AT2(REG0, REG)))       \
  V(MOVW_RM_A_R0_RN, FORMAT_NM, "mov.w", PAIR(REG, AT2(REG0, REG)))       \
  V(MOVL_RM_A_R0_RN, FORMAT_NM, "mov.l", PAIR(REG, AT2(REG0, REG)))       \
  V(MOVB_A_R0_RM_RN, FORMAT_NM, "mov.b", PAIR(AT2(REG0, REG), REG))       \
  V(MOVW_A_R0_RM_RN, FORMAT_NM, "mov.w", PAIR(AT2(REG0, REG), REG))       \
  V(MOVL_A_R0_RM_RN, FORMAT_NM, "mov.l", PAIR(AT2(REG0, REG), REG))       \
  V(MOV_I_RN, FORMAT_NI, "mov", PAIR(SIMM, REG))                          \
  V(MOVW_A_D_PC_RN, FORMAT_ND8, "mov.w", PAIR(AT(ADDR), REG))             \
  V(MOVL_A_D_PC_RN, FORMAT_ND8, "mov.l", PAIR(AT(ADDR), REG))             \
  V(MOVB_A_D_GBR_R0, FORMAT_D, "mov.b", PAIR(AT2(DISP, GBR), REG0))       \
  V(MOVW_A_D_GBR_R0, FORMAT_D, "mov.w", PAIR(AT2(DISP, GBR), REG0))       \
  V(MOVL_A_D_GBR_R0, FORMAT_D, "mov.l", PAIR(AT2(DISP, GBR), REG0))       \
  V(MOVB_R0_A_D_GBR, FORMAT_D, "mov.b", PAIR(REG0, AT2(DISP, GBR)))       \
  V(MOVW_R0_A_D_GBR, FORMAT_D, "mov.w", PAIR(REG0, AT2(DISP, GBR)))       \
  V(MOVL_R0_A_D_GBR, FORMAT_D, "mov.l", PAIR(REG0, AT2(DISP, GBR)))       \
  V(MOVB_R0_A_D_RN, FORMAT_ND4, "mov.b", PAIR(REG0, AT2(DISP, REG)))      \
  V(MOVW_R0_A_D_RN, FORMAT_ND4, "mov.w", PAIR(REG0, AT2(DISP, REG)))      \
  V(MOVL_RM_A_D_RN, FORMAT_NMD, "mov.l", PAIR(REG, AT2(DISP, REG)))       \
  V(MOVB_A_D_RM_R0, FORMAT_MD, "mov.b", PAIR(AT2(DISP, REG), REG0))       \
  V(MOVW_A_D_RM_R0, FORMAT_MD, "mov.w", PAIR(AT2(DISP, REG), REG0))       \
  V(MOVL_A_D_RM_RN, FORMAT_NMD, "mov.l", PAIR(AT2(REG, DISP), REG))       \
  V(MOVA_A_D_PC_R0, FORMAT_D, "mov", PAIR(ADDR, REG0))                    \
  V(MOVT_RN, FORMAT_N, "movt", REG)                                       \
  V(MULL_RM_RN, FORMAT_NM, "mul.l", REG_PAIR)                             \
  V(MULSW_RM_RN, FORMAT_NM, "muls.w", REG_PAIR)                           \
  V(MULUW_RM_RN, FORMAT_NM, "mulu.w", REG_PAIR)                           \
  V(NEGC_RM_RN, FORMAT_NM, "negc", REG_PAIR)                              \
  V(NEG_RM_RN, FORMAT_NM, "neg", REG_PAIR)                                \
  V(NOP, FORMAT_0, "nop", "")                                             \
  V(NOT_RM_RN, FORMAT_NM, "not", REG_PAIR)                                \
  V(OR_RM_RN, FORMAT_NM, "or", REG_PAIR)                                  \
  V(OR_I_R0, FORMAT_I, "or", PAIR(IMM, REG0))                             \
  V(ORB_I_A_R0_GBR, FORMAT_I, "or.b", PAIR(IMM, AT2(REG0, GBR)))          \
  V(ROTCL_RN, FORMAT_N, "rotcl", REG)                                     \
  V(ROTCR_RN, FORMAT_N, "rotcr", REG)                                     \
  V(ROTL_RN, FORMAT_N, "rotl", REG)                                       \
  V(ROTR_RN, FORMAT_N, "rotr", REG)                                       \
  V(RTE, FORMAT_0, "rte", "")                                             \
  V(RTS, FORMAT_0, "rts", "")                                             \
  V(SETT, FORMAT_0, "sett", "")                                           \
  V(SHAL_RN, FORMAT_N, "shal", REG)                                       \
  V(SHAR_RN, FORMAT_N, "shar", REG)                                       \
  V(SHLL_RN, FORMAT_N, "shll", REG)                                       \
  V(SHLL2_RN, FORMAT_N, "shll2", REG)                                     \
  V(SHLL8_RN, FORMAT_N, "shll8", REG)                                     \
  V(SHLL16_RN, FORMAT_N, "shll16", REG)                                   \
  V(SHLR_RN, FORMAT_N, "shlr", REG)                                       \
  V(SHLR2_RN, FORMAT_N, "shlr2", REG)                                     \
  V(SHLR8_RN, FORMAT_N, "shlr8", REG)                                     \
  V(SHLR16_RN, FORMAT_N, "shlr16", REG)                                   \
  V(SLEEP, FORMAT_0, "sleep", "")                                         \
  V(STC_SR_RN, FORMAT_N, "stc", PAIR(SR, REG))                            \
  V(STC_GBR_RN, FORMAT_N, "stc", PAIR(GBR, REG))                          \
  V(STC_VBR_RN, FORMAT_N, "stc", PAIR(VBR, REG))                          \
  V(STCL_SR_AMRN, FORMAT_N, "stc.l", PAIR(SR, AT_MINUS(REG)))             \
  V(STCL_GBR_AMRN, FORMAT_N, "stc.l", PAIR(GBR, AT_MINUS(REG)))           \
  V(STCL_VBR_AMRN, FORMAT_N, "stc.l", PAIR(VBR, AT_MINUS(REG)))           \
  V(STS_MACH_RN, FORMAT_N, "sts", PAIR(MACH, REG))                        \
  V(STS_MACL_RN, FORMAT_N, "sts", PAIR(MACL, REG))                        \
  V(STS_PR_RN, FORMAT_N, "sts", PAIR(PR, REG))                            \
  V(STSL_MACH_AMRN, FORMAT_N, "sts.l", PAIR(MACH, AT_MINUS(REG)))         \
  V(STSL_MACL_AMRN, FORMAT_N, "sts.l", PAIR(MACL, AT_MINUS(REG)))         \
  V(STSL_PR_AMRN, FORMAT_N, "sts.l", PAIR(PR, AT_MINUS(REG)))             \
  V(SUB_RM_RN, FORMAT_NM, "sub", REG_PAIR)                                \
  V(SUBC_RM_RN, FORMAT_NM, "subc", REG_PAIR)                              \
  V(SUBV_RM_RN, FORMAT_NM, "subv", REG_PAIR)                              \
  V(SWAPB_RM_RN, FORMAT_NM, "swap.b", REG_PAIR)                           \
  V(SWAPW_RM_RN, FORMAT_NM, "swap.w", REG_PAIR)                           \
  V(TASB_ARN, FORMAT_N, "tas.b", AT(REG))                                 \
  V(TRAPA_I, FORMAT_I, "trapa", IMM)                                      \
  V(TST_RM_RN, FORMAT_NM, "tst", REG_PAIR)                                \
  V(TST_I_R0, FORMAT_I, "tst", PAIR(IMM, REG0))                           \
  V(TSTB_I_A_R0_GBR, FORMAT_I, "tst.b", PAIR(IMM, AT2(REG0, GBR)))        \
  V(XOR_RM_RN, FORMAT_NM, "xor", REG_PAIR)                                \
  V(XOR_I_R0, FORMAT_I, "xor", PAIR(IMM, REG0))                           \
  V(XORB_I_A_R0_GBR, FORMAT_I, "xor.b", PAIR(IMM, AT2(REG0, GBR)))        \
  V(XTRCT_RM_RN, FORMAT_NM, "xtrct", REG_PAIR)

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
  REGISTER_GBR = 16,
  REGISTER_VBR,
  REGISTER_MACH,
  REGISTER_MACL,
  REGISTER_PR,
  REGISTER_SR,
  NUM_REGISTERS,

  REGISTER_PC,   /* Dummy value used in print_registers only. */
} Register;

typedef enum {
  STAGE_NONE,
  STAGE_IF, /* Instruction fetch. */
  STAGE_ID, /* Instruction decode. */
  STAGE_EX, /* Instruction execute. */
  STAGE_MA, /* Memory access. */
  STAGE_WB, /* Write back. */
} Stage;

typedef enum {
  MEMORY_MAP_INVALID,
  MEMORY_MAP_ROM, /* 0xe0000000.. */
} MemoryMapType;

typedef struct {
  MemoryMapType type;
  Address addr;
} MemoryTypeAddressPair;

typedef enum {
  MEMORY_ACCESS_READ_U32,
  MEMORY_ACCESS_WRITE_U32,
} MemoryAccessType;

typedef enum {
  STAGE_RESULT_OK,
  STAGE_RESULT_UNIMPLEMENTED,
  STAGE_RESULT_STALL,
  STAGE_RESULT_WRITEBACK_AS_EXECUTE,
} StageResult;

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
  Address addr;
  bool active;
} StageIF;

typedef struct {
  u32 code;
  bool active;
} StageID;

typedef struct {
  Instr instr;
  bool active;
} StageEX;

typedef struct {
  MemoryAccessType type;
  Address addr;
  union {
    u8 v8;
    u16 v16;
    u32 v32;
    u32 wb_reg;
  };
  bool active;
} StageMA;

typedef struct {
  u32 reg;
  u32 val;
  bool active;
} StageWB;

typedef struct {
  StageIF if_;
  StageID id;
  StageEX ex;
  StageMA ma;
  StageWB wb;
} Pipeline;

typedef struct {
  u32 reg[NUM_REGISTERS];
  u32 pc;
  Pipeline pipeline;
} State;

typedef struct {
  State state;
  Buffer rom;
} Emulator;

const char* s_reg_name[NUM_REGISTERS] = {
#define V(name) MAKE_BOLD(#name),
    FOREACH_REGISTER(V)
#undef V
};

OpInfo s_op_info[] = {
#define V(name, format, op_str, fmt_str) {format, op_str, fmt_str},
    FOREACH_OP(V)
#undef V
};

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

MemoryTypeAddressPair map_address(Emulator* e, Address address) {
  switch ((address >> 24) & 0xf) {
    case 0xe:
      if (address < 0x0e000000 + e->rom.size) {
        return (MemoryTypeAddressPair){.type = MEMORY_MAP_ROM,
                                       .addr = address - 0x0e000000};
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

bool instr_has_n(InstrFormat format) {
  return format == FORMAT_N || format == FORMAT_NM || format == FORMAT_NMD ||
         format == FORMAT_ND4 || format == FORMAT_ND8 || format == FORMAT_NI;
}

bool instr_has_m(InstrFormat format) {
  return format == FORMAT_M || format == FORMAT_NM || format == FORMAT_MD ||
         format == FORMAT_NMD;
}

void print_instr(Emulator* e, Instr instr, bool print_memory) {
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

  if (print_memory) {
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

Instr format_ni(u16 code, Op op) {
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

Instr format_si(u16 code, Op op) {
  return (Instr){.op = op, .i = SIGN_EXTEND(code & 0xff, 8)};
}

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
          case 0x00: return format_m(code, BSRF_RM);
          case 0x20: return format_m(code, BRAF_RM);
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
      return format_ni(code, ADD_I_RN);

    case 0x8:
      // clang-format off
    switch (code & 0x0f00) {
      case 0x000: return format_nd4(code, MOVB_R0_A_D_RN, 1);
      case 0x100: return format_nd4(code, MOVW_R0_A_D_RN, 2);
      case 0x400: return format_md(code, MOVB_A_D_RM_R0, 1);
      case 0x500: return format_md(code, MOVW_A_D_RM_R0, 2);
      case 0x800: return format_si(code, CMPEQ_I_R0);
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
      return format_ni(code, MOV_I_RN);

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
    u16 code = read_u16(e, address);
    printf(YELLOW "[%08x]: " WHITE "%04x ", address, code);
    Instr instr = decode(address, code);
    if (instr.op == INVALID_OP) {
      printf(MAGENTA ".WORD %04x" WHITE, code);
    } else {
      print_instr(e, instr, true);
    }

    printf("\n");
  }
}

void init_emulator(Emulator* e, Buffer* rom) {
  ZERO_MEMORY(*e);
  e->state.reg[REGISTER_SR] = 0xf0;
  e->rom = *rom;
  e->state.pc = 0x0e000480;
  e->state.pipeline.if_.active = true;
}

void print_registers(Emulator* e, int n, ...) {
  if (n == 0) {
    return;
  }

  printf("  ; ");

  va_list args;
  va_start(args, n);
  int i;
  for (i = 0; i < n; ++i) {
    int reg = va_arg(args, int);
    const char* name;
    u32 val;
    if (reg == REGISTER_PC) {
      name = MAKE_BOLD("pc");
      val = e->state.pc;
    } else {
      name = s_reg_name[reg];
      val = e->state.reg[reg];
    }
    printf("%s:%08x ", name, val);
  }
  va_end(args);
}

void print_stage(const char* name) {
  printf(CYAN "%9s:" WHITE " ", name);
}

void stage_fetch(Emulator* e) {
  StageIF* if_ = &e->state.pipeline.if_;
  StageID* id = &e->state.pipeline.id;

  if (!if_->active) {
    return;
  }

  u32 pc = e->state.pc;
  u16 code = read_u16(e, pc);
  id->code = code;
  id->active = true;
  e->state.pc += 2;

  print_stage("fetch");
  printf("[0x%08x] => 0x%04x\n", pc, code);
}

void stage_decode(Emulator* e) {
  StageID* id = &e->state.pipeline.id;
  StageEX* ex = &e->state.pipeline.ex;

  if (!id->active) {
    return;
  }

  id->active = false;

  Instr instr = decode(e->state.pc - 2, id->code);
  *ex = (StageEX){.active = true, .instr = instr};

  print_stage("decode");
  printf("      0x%04x => ", id->code);
  print_instr(e, instr, false);
  printf("\n");
}

StageResult stage_execute(Emulator* e) {
  StageResult result = STAGE_RESULT_OK;
  StageEX* ex = &e->state.pipeline.ex;
  StageMA* ma = &e->state.pipeline.ma;
  StageWB* wb = &e->state.pipeline.wb;

  if (!ex->active) {
    return result;
  }

  ex->active = false;

  Instr instr = ex->instr;

  print_stage("execute");
  print_instr(e, instr, false);
  printf("  ");

  if (wb->active) {
    InstrFormat format = s_op_info[instr.op].format;
    /* If the following writeback stage will write to the same destination
     * register as this instruction, we have to stall. */
    if (instr_has_n(format) && wb->reg == instr.n) {
      return STAGE_RESULT_STALL;
    }

    /* If the following writeback stage will write to a register that will be
     * used below, it appears to not stall, and instead will forward that
     * value early. This isn't mentioned explicitly, but the documentation says
     * that the stall occurs when the "destination (not the source) of
     * instruction 2" uses the same register as the load. */
    if (instr_has_m(format) && wb->reg == instr.m) {
      e->state.reg[instr.m] = wb->val;
    }
  }

  switch (instr.op) {
    /* bra */
    case BRA:
      e->state.pc = instr.d;
      result = STAGE_RESULT_STALL;
      print_registers(e, 1, REGISTER_PC);
      break;

    /* jsr @rm */
    case JSR_ARM:
      e->state.reg[REGISTER_PR] = e->state.pc;
      e->state.pc = e->state.reg[instr.m];
      result = STAGE_RESULT_STALL;
      print_registers(e, 2, REGISTER_PC, REGISTER_PR);
      break;

    /* ldc.l @rm+, vbr */
    case LDCL_ARMP_VBR:
      *ma = (StageMA){.active = true,
                      .type = MEMORY_ACCESS_READ_U32,
                      .addr = e->state.reg[instr.m],
                      .wb_reg = REGISTER_VBR};
      e->state.reg[instr.m] += 4;
      result = STAGE_RESULT_STALL;
      print_registers(e, 1, instr.m);
      break;

    /* mov #i, rn */
    case MOV_I_RN:
      e->state.reg[instr.n] = instr.i;
      break;

    /* mov.l @(disp, pc), rn */
    case MOVL_A_D_PC_RN:
      *ma = (StageMA){.active = true,
                      .type = MEMORY_ACCESS_READ_U32,
                      .addr = instr.d,
                      .wb_reg = instr.n};
      break;

    /* mov.l @rm+, rn */
    case MOVL_ARMP_RN:
      *ma = (StageMA){.active = true,
                      .type = MEMORY_ACCESS_READ_U32,
                      .addr = e->state.reg[instr.m],
                      .wb_reg = instr.n};
      e->state.reg[instr.m] += 4;
      print_registers(e, 1, instr.m);
      break;

    /* mov.l rm, @-rn */
    case MOVL_RM_AMRN:
      e->state.reg[instr.n] -= 4;
      *ma = (StageMA){.active = true,
                      .type = MEMORY_ACCESS_WRITE_U32,
                      .addr = e->state.reg[instr.n],
                      .v32 = e->state.reg[instr.m]};
      print_registers(e, 2, instr.m, instr.n);
      break;

    /* mov.l rm, @rn */
    case MOVL_RM_ARN:
      *ma = (StageMA){.active = true,
                      .type = MEMORY_ACCESS_WRITE_U32,
                      .addr = e->state.reg[instr.n],
                      .v32 = e->state.reg[instr.m]};
      print_registers(e, 2, instr.m, instr.n);
      break;

    /* mova @(disp, pc), r0 */
    case MOVA_A_D_PC_R0:
      e->state.reg[0] = instr.d;
      print_registers(e, 1, 0);
      break;

    /* nop */
    case NOP:
      break;

    /* sts.l pr, @-rn */
    case STSL_PR_AMRN:
      e->state.reg[instr.n] -= 4;
      *ma = (StageMA){.active = true,
                      .type = MEMORY_ACCESS_WRITE_U32,
                      .addr = e->state.reg[REGISTER_PR],
                      .v32 = e->state.reg[instr.n]};
      print_registers(e, 2, REGISTER_PR, instr.n);
      break;

    default:
      result = STAGE_RESULT_UNIMPLEMENTED;
      break;
  }

  printf("\n");

  if (result == STAGE_RESULT_UNIMPLEMENTED) {
    UNREACHABLE("unimplemented instruction '%s'\n", s_op_info[instr.op].op_str);
  }

  return result;
}

StageResult stage_memory_access(Emulator* e) {
  StageResult result = STAGE_RESULT_OK;
  StageEX* ex = &e->state.pipeline.ex;
  StageMA* ma = &e->state.pipeline.ma;
  StageWB* wb = &e->state.pipeline.wb;

  if (!ma->active) {
    return result;
  }

  ma->active = false;

  print_stage("access");

  switch (e->state.pipeline.ma.type) {
    case MEMORY_ACCESS_READ_U32: {
      Address addr = ma->addr;
      u32 val = read_u32(e, addr);
      *wb = (StageWB){.active = true, .reg = ma->wb_reg, .val = val};
      printf("[0x%08x] => 0x%08x\n", addr, val);
      break;
    }

    case MEMORY_ACCESS_WRITE_U32: {
      Address addr = ma->addr;
      u32 val = ma->v32;
      // u32 val = read_u32(e, addr);
      printf("  0x%08x => [0x%08x]\n", val, addr);
      break;
    }
  }

  /* For now, this will always stall since the IF stage is always active. It's
   * not supposed to stall if the next instruction is already fetched. This
   * happens when fetching instructions from on-chip ROM/cache, so it can fetch
   * two instructions (32-bits) instead of one (16-bits). */
  if (e->state.pipeline.if_.active) {
    /* MA and IF contention. */
    result = STAGE_RESULT_STALL;
  }

  return result;
}

StageResult stage_writeback(Emulator* e) {
  StageWB* wb = &e->state.pipeline.wb;

  if (!wb->active) {
    return STAGE_RESULT_OK;
  }

  wb->active = false;

  u32 reg = wb->reg;
  u32 val = wb->val;
  e->state.reg[reg] = val;

  if (reg == REGISTER_GBR || reg == REGISTER_VBR || reg == REGISTER_SR) {
    /* Writing to GBR, VBR and SR happen in execute stage; fake that here. */
    print_stage("execute*");
    printf("%s:%08x\n", s_reg_name[reg], val);
    return STAGE_RESULT_WRITEBACK_AS_EXECUTE;
  } else {
    print_stage("writeback");
    printf("%s:%08x\n", s_reg_name[reg], val);
    return STAGE_RESULT_OK;
  }
}

void step(Emulator* e) {
  printf(YELLOW "--- step ---\n" WHITE);
  if (stage_writeback(e) != STAGE_RESULT_WRITEBACK_AS_EXECUTE) {
    if (stage_memory_access(e) == STAGE_RESULT_STALL) {
      return;
    }

    if (stage_execute(e) == STAGE_RESULT_STALL) {
      return;
    }
  }

  stage_decode(e);
  stage_fetch(e);
}

int main(int argc, char** argv) {
  --argc; ++argv;
  int result = 1;
  CHECK_MSG(argc == 1, "no rom file given.\n");
  const char* rom_filename = argv[0];

  Buffer rom;
  CHECK(SUCCESS(read_file(rom_filename, &rom)));
  Emulator e;
  init_emulator(&e, &rom);

  int i;
  for (i = 0; i < 100; ++i) {
    step(&e);
  }

  return 0;
  ON_ERROR_RETURN;
}
