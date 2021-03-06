#include <assert.h>
#include <ctype.h>
#include <memory.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define USE_COLOR 1
#define INSTR_COLUMNS 30

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

#define BIOS_SIZE (64 * 1024)
#define RAM_SIZE (512 * 1024)

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
  SR_T = 1 << 0,
  SR_S = 1 << 1,
  SR_I0 = 1 << 4,
  SR_I1 = 1 << 5,
  SR_I2 = 1 << 6,
  SR_I3 = 1 << 7,
  SR_Q = 1 << 8,
  SR_M = 1 << 9,
} SrBits;

typedef enum {
  REGISTER_GBR = 16,
  REGISTER_VBR,
  REGISTER_MACH,
  REGISTER_MACL,
  REGISTER_PR,
  REGISTER_SR,
  NUM_REGISTERS,

  /* Dummy value used in print_registers only. */
  REGISTER_PC,
  REGISTER_ADDR,
  REGISTER_U8,
  REGISTER_T,
} Register;

typedef enum {
  MEMORY_MAP_INVALID,
  MEMORY_MAP_BIOS, /* 0x00000000..0x00010000 (?) */
  MEMORY_MAP_RAM,  /* 0x09000000..0x0907ffff */
  MEMORY_MAP_IO,   /* 0x0c04????..0x0c05???? */
  MEMORY_MAP_ROM,  /* 0x0e000000..0x0e000000 */
} MemoryMapType;

typedef struct {
  MemoryMapType type;
  Address addr;
} MemoryTypeAddressPair;

typedef enum {
  MEMORY_ACCESS_READ_U8_WB,
  MEMORY_ACCESS_READ_U16_WB,
  MEMORY_ACCESS_READ_U32_WB,
  MEMORY_ACCESS_READ_U8_EX,
  MEMORY_ACCESS_READ_U16_EX,
  MEMORY_ACCESS_READ_U32_EX,
  MEMORY_ACCESS_WRITE_U8,
  MEMORY_ACCESS_WRITE_U16,
  MEMORY_ACCESS_WRITE_U32,
  MEMORY_ACCESS_READ_MACL,
  MEMORY_ACCESS_MULTIPLY,
} MemoryAccessType;

typedef enum {
  MULTIPLIER_MULU,
  MULTIPLIER_MACW,
  MULTIPLIER_MACL,
  MULTIPLIER_DMULSL,
  MULTIPLIER_DMULUL,
  MULTIPLIER_MULL,
} MultiplierType;

typedef struct {
  MultiplierType type;
  u32 rm, rn;
} Multiplier;

typedef enum {
  STAGE_RESULT_OK,
  STAGE_RESULT_UNIMPLEMENTED,
  STAGE_RESULT_STALL,
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
  Address iaddr;
  bool active;
  /* Used for instructions that use the same stage multiple times. */
  int step;
} Stage;

typedef struct {
  Stage s;
} StageIF;

typedef struct {
  Stage s;
  u32 code;
  u32 pc;
} StageID;

typedef struct {
  Stage s;
  Instr instr;
} StageEX;

typedef struct {
  Stage s;
  MemoryAccessType type;
  Address addr;
  union {
    u8 v8;
    u16 v16;
    u32 v32;
    u32 wb_reg;
    Multiplier mul;
  };
} StageMA;

typedef struct {
  Stage s;
  Multiplier mul;
} StageMM;

typedef struct {
  Stage s;
  u32 reg;
  u32 val;
} StageWB;

typedef struct {
  StageIF if_;
  StageID id;
  StageEX ex;
  StageMA ma;
  StageMM mm;
  StageWB wb;
} Pipeline;

typedef struct {
  u32 reg[NUM_REGISTERS];
  u32 pc;
  Pipeline pipeline;
  u8 ram[RAM_SIZE];
} State;

typedef struct {
  State state;
  Buffer rom;
  int verbosity;
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

MemoryTypeAddressPair map_address(Emulator* e, Address addr) {
  MemoryMapType type;
  Address base = addr & 0x0f000000;
  switch ((addr >> 24) & 0xf) {
    case 0x0:
      /* TODO(binji): Seems to be BIOS routines; figure out what these do and
       * how big this region is. */
      if (addr >= BIOS_SIZE) goto invalid;
      type = MEMORY_MAP_BIOS;
      break;

    case 0x9:
      if (addr >= base + RAM_SIZE) goto invalid;
      type = MEMORY_MAP_RAM;
      break;

    case 0xe:
      if (addr >= base + e->rom.size) goto invalid;
      type = MEMORY_MAP_ROM;
      break;

    invalid:
    default:
      return (MemoryTypeAddressPair){.type = MEMORY_MAP_INVALID};
  }

  return (MemoryTypeAddressPair){.type = type, .addr = addr - base};
}

u16 read_u16_raw(Emulator* e, Address addr) {
  /* HACK: just RTS/NOP for any called routine. */
  // clang-format off
  static u16 s_bios[0x10000] = {
      [0x668] = 0x000b,  [0x66a] = 0x0009,
      [0x69c] = 0x000b,  [0x69e] = 0x0009,
      [0x3e64] = 0x000b, [0x3e66] = 0x0009,
      [0x437c] = 0x000b, [0x437e] = 0x0009,
      [0x5f4c] = 0x000b, [0x5f4e] = 0x0009,
      [0x613c] = 0x000b, [0x613e] = 0x0009,
      [0x61a0] = 0x000b, [0x61a2] = 0x0009,
      [0x6644] = 0x000b, [0x6646] = 0x0009,
      [0x66d0] = 0x000b, [0x66d2] = 0x0009,
      [0x6a0e] = 0x000b, [0x6a10] = 0x0009,
      [0x6a48] = 0x000b, [0x6a4a] = 0x0009,
      [0x6a5a] = 0x000b, [0x6a5c] = 0x0009,
      [0x6ac0] = 0x000b, [0x6ac2] = 0x0009,
      [0x6b50] = 0x000b, [0x6b52] = 0x0009,
      [0x7d96] = 0x000b, [0x7d98] = 0x0009,
  };
  // clang-format on

  MemoryTypeAddressPair pair = map_address(e, addr);
  switch (pair.type) {
    case MEMORY_MAP_BIOS:
      printf(YELLOW "reading BIOS  @0x%08x\n" WHITE, addr);
      return s_bios[pair.addr];

    case MEMORY_MAP_RAM:
      return (e->state.ram[pair.addr] << 8) | e->state.ram[pair.addr + 1];

    case MEMORY_MAP_ROM: {
      /* TODO(binji): assumes little-endian. */
      u16 value;
      memcpy(&value, &e->rom.data[pair.addr], sizeof(u16));
      return value;
    }

    default:
    case MEMORY_MAP_INVALID:
      printf(YELLOW "invalid memory read  @0x%08x\n" WHITE, addr);
      return 0xffff;
  }
}

u8 read_u8(Emulator* e, Address addr) {
  u16 x = read_u16_raw(e, addr & ~1);
  return addr & 1 ? x >> 8 : x & 0xff;
}

u16 read_u16(Emulator* e, Address addr) {
  assert((addr & 1) == 0);
  return read_u16_raw(e, addr);
}

u32 read_u32(Emulator* e, Address addr) {
  assert((addr & 3) == 0);
  return (read_u16_raw(e, addr) << 16) | read_u16_raw(e, addr + 2);
}

void write_u8(Emulator* e, Address addr, u8 value) {
  MemoryTypeAddressPair pair = map_address(e, addr);
  switch (pair.type) {
    case MEMORY_MAP_RAM:
      e->state.ram[pair.addr] = value;
      break;

    default:
      printf(YELLOW "invalid memory write @0x%08x <= 0x%02x\n" WHITE, addr,
             value);
      break;
  }
}

void write_u16(Emulator* e, Address addr, u16 value) {
  /* TODO(binji): this should be an exception instead of assert. */
  assert((addr & 1) == 0);

  MemoryTypeAddressPair pair = map_address(e, addr);
  switch (pair.type) {
    case MEMORY_MAP_RAM:
      e->state.ram[pair.addr] = value >> 8;
      e->state.ram[pair.addr + 1] = value;
      break;

    default:
      printf(YELLOW "invalid memory write @0x%08x <= 0x%04x\n" WHITE, addr,
             value);
      break;
  }
}

void write_u32(Emulator* e, Address addr, u32 value) {
  /* TODO(binji): this should be an exception instead of assert. */
  assert((addr & 3) == 0);

  MemoryTypeAddressPair pair = map_address(e, addr);
  switch (pair.type) {
    case MEMORY_MAP_RAM:
      e->state.ram[pair.addr] = value >> 24;
      e->state.ram[pair.addr + 1] = value >> 16;
      e->state.ram[pair.addr + 2] = value >> 8;
      e->state.ram[pair.addr + 3] = value;
      break;

    default:
      printf(YELLOW "invalid memory write @0x%08x <= 0x%08x\n" WHITE, addr,
             value);
      break;
  }
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
  char buf[100];
  char* bufp = buf;

#define SNCAT(...) \
  bufp += snprintf(bufp, sizeof(buf) - (bufp - buf), __VA_ARGS__)

  OpInfo op_info = s_op_info[instr.op];
  SNCAT(GREEN "%s" WHITE " ", op_info.op_str);

  // clang-format off
  switch (op_info.format) {
    case FORMAT_0: break;
    case FORMAT_M: SNCAT(op_info.fmt_str, instr.m); break;
    case FORMAT_N: SNCAT(op_info.fmt_str, instr.n); break;
    case FORMAT_NM: SNCAT(op_info.fmt_str, instr.m, instr.n); break;
    case FORMAT_MD: SNCAT(op_info.fmt_str, instr.d, instr.m); break;
    case FORMAT_NMD: SNCAT(op_info.fmt_str, instr.m, instr.d, instr.n); break;
    case FORMAT_D:
    case FORMAT_D12: SNCAT(op_info.fmt_str, instr.d); break;
    case FORMAT_ND4:
    case FORMAT_ND8: SNCAT(op_info.fmt_str, instr.d, instr.n); break;
    case FORMAT_I: SNCAT(op_info.fmt_str, instr.i); break;
    case FORMAT_NI: SNCAT(op_info.fmt_str, instr.i, instr.n); break;
  }
  // clang-format on

#undef SNCAT

  /* Count the length of the instruction, skipping color escape codes. */
  int count = 0;
  const char* p;
  for (p = buf; *p; ++p) {
    if (*p == '\x1b') {
      while (*p && *p != 'm') p++;
    } else {
      ++count;
    }
  }

  /* Pad out the instruction with spaces, so whatever follows is aligned. */
  printf("%s%*s", buf, INSTR_COLUMNS - count, "");

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
      printf("; 0x%08x", val);
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

void disassemble(Emulator* e, size_t num_instrs, u32 addr) {
  size_t i;
  for (i = 0; i < num_instrs; ++i, addr += 2) {
    u16 code = read_u16(e, addr);
    printf(YELLOW "[%08x]: " WHITE "%04x ", addr, code);
    Instr instr = decode(addr, code);
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
  e->verbosity = 0;
  e->state.reg[REGISTER_SR] = 0xf0;
  e->rom = *rom;
  e->state.pc = 0x0e000480;
  e->state.pipeline.if_.s.active = true;
}

void print_registers(Emulator* e, int n, ...) {
  if (n == 0 || e->verbosity == 0) {
    return;
  }

  printf("; ");

  u32 seen = 0;

  va_list args;
  va_start(args, n);
  int i;
  for (i = 0; i < n; ++i) {
    int reg = va_arg(args, int);

    /* Only print a given register once. */
    u32 mask = 1 << reg;
    if (seen & mask) {
      continue;
    }
    seen |= mask;

    const char* name;
    u32 val;
    switch (reg) {
      case REGISTER_PC:
        name = MAKE_BOLD("pc");
        val = e->state.pc;
        goto print_u32;

      case REGISTER_ADDR:
        name = MAKE_BOLD("addr");
        val = va_arg(args, u32);
        goto print_u32;

      case REGISTER_U8:
        name = MAKE_BOLD("u8");
        val = va_arg(args, u32);
        goto print_u8;

      case REGISTER_T:
        name = MAKE_BOLD("t");
        val = e->state.reg[REGISTER_SR] & SR_T;
        goto print_u8;

      default:
        name = s_reg_name[reg];
        val = e->state.reg[reg];
        goto print_u32;

      print_u32:
        printf("%s:%08x ", name, val);
        break;

      print_u8:
        printf("%s:%02x ", name, val);
        break;
    }
  }
  va_end(args);
}

void print_stage(Stage s, const char* name) {
  printf(CYAN "%9s" WHITE "[%08x]: ", name, s.iaddr);
}

void stage_fetch(Emulator* e) {
  StageIF* if_ = &e->state.pipeline.if_;
  StageID* id = &e->state.pipeline.id;

  if (!if_->s.active) {
    return;
  }

  u32 pc = e->state.pc;
  if_->s.iaddr = pc;
  u16 code = read_u16(e, pc);
  *id = (StageID){
      .s = {.active = true, .iaddr = pc, .step = 0}, .code = code, .pc = pc};
  e->state.pc += 2;

  if (e->verbosity > 1) {
    print_stage(if_->s, "fetch");
    printf("[0x%08x] => 0x%04x\n", pc, code);
  }
}

void stage_decode(Emulator* e) {
  StageID* id = &e->state.pipeline.id;
  StageEX* ex = &e->state.pipeline.ex;

  if (!id->s.active) {
    return;
  }

  Instr instr = decode(e->state.pc - 2, id->code);
  *ex = (StageEX){.s = id->s, .instr = instr};

  id->s.active = false;

  if (e->verbosity > 1) {
    print_stage(id->s, "decode");
    printf("      0x%04x => ", id->code);
    print_instr(e, instr, false);
    printf("\n");
  }
}

static StageMA stage_ma_read_u8_wb(Emulator* e, Address addr, Register reg) {
  return (StageMA){.s = e->state.pipeline.ex.s,
                   .type = MEMORY_ACCESS_READ_U8_WB,
                   .addr = addr,
                   .wb_reg = reg};
}

static StageMA stage_ma_read_u8_ex(Emulator* e, Address addr) {
  return (StageMA){.s = e->state.pipeline.ex.s,
                   .type = MEMORY_ACCESS_READ_U8_EX,
                   .addr = addr};
}

static StageMA stage_ma_write_u8(Emulator* e, Address addr, u8 val) {
  return (StageMA){.s = e->state.pipeline.ex.s,
                   .type = MEMORY_ACCESS_WRITE_U8,
                   .addr = addr,
                   .v8 = val};
}

static StageMA stage_ma_read_u16_wb(Emulator* e, Address addr, Register reg) {
  return (StageMA){.s = e->state.pipeline.ex.s,
                   .type = MEMORY_ACCESS_READ_U16_WB,
                   .addr = addr,
                   .wb_reg = reg};
}

static StageMA stage_ma_write_u16(Emulator* e, Address addr, u16 val) {
  return (StageMA){.s = e->state.pipeline.ex.s,
                   .type = MEMORY_ACCESS_WRITE_U16,
                   .addr = addr,
                   .v16 = val};
}

static StageMA stage_ma_read_u32_wb(Emulator* e, Address addr, Register reg) {
  return (StageMA){.s = e->state.pipeline.ex.s,
                   .type = MEMORY_ACCESS_READ_U32_WB,
                   .addr = addr,
                   .wb_reg = reg};
}

static StageMA stage_ma_read_u32_ex(Emulator* e, Address addr) {
  return (StageMA){.s = e->state.pipeline.ex.s,
                   .type = MEMORY_ACCESS_READ_U32_EX,
                   .addr = addr};
}

static StageMA stage_ma_write_u32(Emulator* e, Address addr, u32 val) {
  return (StageMA){.s = e->state.pipeline.ex.s,
                   .type = MEMORY_ACCESS_WRITE_U32,
                   .addr = addr,
                   .v32 = val};
}

static void set_sr_t_if(Emulator* e, bool cond) {
  u32* regs = &e->state.reg[0];
  regs[REGISTER_SR] &= ~SR_T;
  regs[REGISTER_SR] |= cond ? SR_T : 0;
}

StageResult stage_execute(Emulator* e) {
  StageResult result = STAGE_RESULT_OK;
  StageID* id = &e->state.pipeline.id;
  StageEX* ex = &e->state.pipeline.ex;
  StageMA* ma = &e->state.pipeline.ma;
  StageWB* wb = &e->state.pipeline.wb;

  if (!ex->s.active) {
    return result;
  }

  Instr instr = ex->instr;

  if (e->verbosity > 0) {
    print_stage(ex->s, "execute");
    print_instr(e, instr, false);
  }

  if (wb->s.active) {
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

  u32* regs = &e->state.reg[0];

  switch (instr.op) {
    /* add rm, rn */
    case ADD_RM_RN:
      regs[instr.n] += regs[instr.m];
      print_registers(e, 2, instr.m, instr.n);
      break;

    /* add imm, rn */
    case ADD_I_RN:
      regs[instr.n] += instr.i;
      print_registers(e, 1, instr.n);
      break;

    /* and rm, rn */
    case AND_RM_RN:
      regs[instr.n] &= regs[instr.m];
      print_registers(e, 2, instr.m, instr.n);
      break;

    /* and imm, r0 */
    case AND_I_R0:
      regs[0] &= instr.i;
      print_registers(e, 1, 0);
      break;

    /* bf */
    case BF:
      if (!(regs[REGISTER_SR] & SR_T)) {
        e->state.pc = instr.d;
        /* TODO(binji): This is actually supposed to disable the decode stage,
         * and fetch from the old pc in this cycle, but throw that fetch away.
         * The behavior here is wrong, but likely not to matter, since it's not
         * often that a discarded fetch will affect behavior. */
        id->s.active = false;
        result = STAGE_RESULT_STALL;
      }
      print_registers(e, 2, REGISTER_T, REGISTER_PC);
      break;

    /* bt */
    case BT:
      if (regs[REGISTER_SR] & SR_T) {
        e->state.pc = instr.d;
        /* TODO(binji): See comment in BF above. */
        id->s.active = false;
        result = STAGE_RESULT_STALL;
      }
      print_registers(e, 2, REGISTER_T, REGISTER_PC);
      break;

    /* bra */
    case BRA:
    bra:
      e->state.pc = instr.d;
      result = STAGE_RESULT_STALL;
      print_registers(e, 1, REGISTER_PC);
      break;

    /* bsr */
    case BSR:
      regs[REGISTER_PR] = e->state.pc;
      goto bra;

    /* cmp/eq rm, rn */
    case CMPEQ_RM_RN:
      set_sr_t_if(e, regs[instr.n] == regs[instr.m]);
      print_registers(e, 3, instr.m, instr.n, REGISTER_T);
      break;

    /* cmp/ge rm, rn */
    case CMPGE_RM_RN:
      set_sr_t_if(e, (s32)regs[instr.n] >= (s32)regs[instr.m]);
      print_registers(e, 3, instr.m, instr.n, REGISTER_T);
      break;

    /* cmp/gt rm, rn */
    case CMPGT_RM_RN:
      set_sr_t_if(e, (s32)regs[instr.n] > (s32)regs[instr.m]);
      print_registers(e, 3, instr.m, instr.n, REGISTER_T);
      break;

    /* cmp/hi rm, rn */
    case CMPHI_RM_RN:
      set_sr_t_if(e, regs[instr.n] > regs[instr.m]);
      print_registers(e, 3, instr.m, instr.n, REGISTER_T);
      break;

    /* cmp/hs rm, rn */
    case CMPHS_RM_RN:
      set_sr_t_if(e, regs[instr.n] >= regs[instr.m]);
      print_registers(e, 3, instr.m, instr.n, REGISTER_T);
      break;

    /* cmp/pz rn */
    case CMPPZ_RN:
      set_sr_t_if(e, (s32)regs[instr.n] >= 0);
      print_registers(e, 2, instr.n, REGISTER_T);
      break;

    /* cmp/eq imm, r0 */
    case CMPEQ_I_R0:
      set_sr_t_if(e, instr.i == regs[0]);
      print_registers(e, 2, 0, REGISTER_T);
      break;

    /* exts.b rm, rn */
    case EXTSB_RM_RN:
      regs[instr.n] = SIGN_EXTEND(regs[instr.m], 8);
      print_registers(e, 2, instr.m, instr.n);
      break;

    /* exts.w rm, rn */
    case EXTSW_RM_RN:
      regs[instr.n] = SIGN_EXTEND(regs[instr.m], 16);
      print_registers(e, 2, instr.m, instr.n);
      break;

    /* extu.b rm, rn */
    case EXTUB_RM_RN:
      regs[instr.n] = regs[instr.m] & 0xff;
      print_registers(e, 2, instr.m, instr.n);
      break;

    /* extu.w rm, rn */
    case EXTUW_RM_RN:
      regs[instr.n] = regs[instr.m] & 0xffff;
      print_registers(e, 2, instr.m, instr.n);
      break;

    /* jmp @rm */
    case JMP_ARM:
      e->state.pc = regs[instr.m];
      result = STAGE_RESULT_STALL;
      print_registers(e, 1, REGISTER_PC);
      break;

    /* jsr @rm */
    case JSR_ARM:
      regs[REGISTER_PR] = e->state.pc;
      e->state.pc = regs[instr.m];
      result = STAGE_RESULT_STALL;
      print_registers(e, 2, REGISTER_PC, REGISTER_PR);
      break;

    /* ldc rm, sr */
    case LDC_RM_SR:
      regs[REGISTER_SR] = regs[instr.m];
      print_registers(e, 1, REGISTER_SR);
      break;

    /* ldc rm, gbr */
    case LDC_RM_GBR:
      regs[REGISTER_GBR] = regs[instr.m];
      print_registers(e, 1, REGISTER_GBR);
      break;

    /* ldc rm, vbr */
    case LDC_RM_VBR:
      regs[REGISTER_VBR] = regs[instr.m];
      print_registers(e, 1, REGISTER_VBR);
      break;

    /* ldc.l @rm+, vbr */
    case LDCL_ARMP_VBR:
      switch (ex->s.step) {
        case 0:
          *ma = stage_ma_read_u32_ex(e, regs[instr.m]);
          regs[instr.m] += 4;
          result = STAGE_RESULT_STALL;
          print_registers(e, 1, instr.m);
          break;

        case 1:
          regs[REGISTER_VBR] = ma->v32;
          print_registers(e, 1, REGISTER_VBR);
          break;
      }
      break;

    /* lds.l @rm+, macl */
    case LDSL_ARMP_MACL:
      /* TODO(binji): handle multiplier contention. */
      *ma = stage_ma_read_u32_wb(e, regs[instr.m], REGISTER_MACL);
      regs[instr.m] += 4;
      print_registers(e, 1, instr.m);
      break;

    /* lds.l @rm+, pr */
    case LDSL_ARMP_PR:
      *ma = stage_ma_read_u32_wb(e, regs[instr.m], REGISTER_PR);
      regs[instr.m] += 4;
      print_registers(e, 1, instr.m);
      break;

    /* mov rm, rn */
    case MOV_RM_RN:
      regs[instr.n] = regs[instr.m];
      print_registers(e, 1, instr.n);
      break;

    /* mov.b rm, @rn */
    case MOVB_RM_ARN:
      *ma = stage_ma_write_u8(e, regs[instr.n], regs[instr.m]);
      print_registers(e, 2, instr.m, instr.n);
      break;

    /* mov.w rm, @rn */
    case MOVW_RM_ARN:
      *ma = stage_ma_write_u16(e, regs[instr.n], regs[instr.m]);
      print_registers(e, 2, instr.m, instr.n);
      break;

    /* mov.l rm, @rn */
    case MOVL_RM_ARN:
    movl_rm_arn:
      *ma = stage_ma_write_u32(e, regs[instr.n], regs[instr.m]);
      print_registers(e, 2, instr.m, instr.n);
      break;

    /* mov.b @rm, rn */
    case MOVB_ARM_RN:
      *ma = stage_ma_read_u8_wb(e, regs[instr.m], instr.n);
      print_registers(e, 1, instr.m);
      break;

    /* mov.w @rm, rn */
    case MOVW_ARM_RN:
      *ma = stage_ma_read_u16_wb(e, regs[instr.m], instr.n);
      print_registers(e, 1, instr.m);
      break;

    /* mov.l @rm, rn */
    case MOVL_ARM_RN:
      *ma = stage_ma_read_u32_wb(e, regs[instr.m], instr.n);
      print_registers(e, 1, instr.m);
      break;

    /* mov.l rm, @-rn */
    case MOVL_RM_AMRN:
      regs[instr.n] -= 4;
      goto movl_rm_arn;

    /* mov.b @rm+, rn */
    case MOVB_ARMP_RN:
      *ma = stage_ma_read_u8_wb(e, regs[instr.m], instr.n);
      regs[instr.m] += 4;
      print_registers(e, 1, instr.m);
      break;

    /* mov.w @rm+, rn */
    case MOVW_ARMP_RN:
      *ma = stage_ma_read_u16_wb(e, regs[instr.m], instr.n);
      regs[instr.m] += 4;
      print_registers(e, 1, instr.m);
      break;

    /* mov.l @rm+, rn */
    case MOVL_ARMP_RN:
      *ma = stage_ma_read_u32_wb(e, regs[instr.m], instr.n);
      regs[instr.m] += 4;
      print_registers(e, 1, instr.m);
      break;

    /* mov.b rm, @(r0, rn) */
    case MOVB_RM_A_R0_RN: {
      u32 addr = regs[0] + regs[instr.n];
      *ma = stage_ma_write_u8(e, addr, instr.m);
      print_registers(e, 2, instr.m, REGISTER_ADDR, addr);
      break;
    }

    /* mov.l rm, @(r0, rn) */
    case MOVL_RM_A_R0_RN: {
      u32 addr = regs[0] + regs[instr.n];
      *ma = stage_ma_write_u32(e, addr, instr.m);
      print_registers(e, 2, instr.m, REGISTER_ADDR, addr);
      break;
    }

    /* mov #i, rn */
    case MOV_I_RN:
      regs[instr.n] = instr.i;
      break;

    /* mov.w @(disp, pc), rn */
    case MOVW_A_D_PC_RN:
      *ma = stage_ma_read_u16_wb(e, instr.d, instr.n);
      break;

    /* mov.l @(disp, pc), rn */
    case MOVL_A_D_PC_RN:
      *ma = stage_ma_read_u32_wb(e, instr.d, instr.n);
      break;

    /* mov.w r0, @(disp, gbr) */
    case MOVW_R0_A_D_GBR: {
      u32 addr = regs[REGISTER_GBR] + instr.d;
      *ma = stage_ma_write_u16(e, addr, regs[0]);
      print_registers(e, 2, 0, REGISTER_ADDR, addr);
      break;
    }

    /* mov.b r0, @(disp, rn) */
    case MOVB_R0_A_D_RN: {
      u32 addr = regs[instr.n] + instr.d;
      *ma = stage_ma_write_u8(e, addr, regs[0]);
      print_registers(e, 2, 0, REGISTER_ADDR, addr);
      break;
    }

    /* mov.w r0, @(disp, rn) */
    case MOVW_R0_A_D_RN: {
      u32 addr = regs[instr.n] + instr.d;
      *ma = stage_ma_write_u16(e, addr, regs[0]);
      print_registers(e, 2, 0, REGISTER_ADDR, addr);
      break;
    }

    /* mov.l rm, @(disp, rn) */
    case MOVL_RM_A_D_RN: {
      u32 addr = regs[instr.n] + instr.d;
      *ma = stage_ma_write_u32(e, addr, instr.m);
      print_registers(e, 2, instr.m, REGISTER_ADDR, addr);
      break;
    }

    /* mov.w @(disp, rm), r0 */
    case MOVW_A_D_RM_R0: {
      u32 addr = regs[instr.m] + instr.d;
      *ma = stage_ma_read_u16_wb(e, addr, 0);
      print_registers(e, 1, REGISTER_ADDR, addr);
      break;
    }

    /* mov.l @(disp, rm), rn */
    case MOVL_A_D_RM_RN: {
      u32 addr = regs[instr.m] + instr.d;
      *ma = stage_ma_read_u32_wb(e, addr, instr.n);
      print_registers(e, 1, REGISTER_ADDR, addr);
      break;
    }

    /* mova @(disp, pc), r0 */
    case MOVA_A_D_PC_R0:
      regs[0] = instr.d;
      print_registers(e, 1, 0);
      break;

    /* movt rn */
    case MOVT_RN:
      regs[instr.n] = regs[REGISTER_SR] & SR_T;
      print_registers(e, 1, instr.n);
      break;

    /* mulu.w rm, rn */
    case MULUW_RM_RN:
      *ma = (StageMA){.s = ex->s,
                      .type = MEMORY_ACCESS_MULTIPLY,
                      .mul = {.type = MULTIPLIER_MULU,
                              .rm = (u16)regs[instr.m],
                              .rn = (u16)regs[instr.n]}};
      print_registers(e, 2, instr.m, instr.n);
      break;

    /* nop */
    case NOP:
      break;

    /* or rm, rn */
    case OR_RM_RN:
      regs[instr.n] |= regs[instr.m];
      print_registers(e, 2, instr.m, instr.n);
      break;

    /* or imm, r0 */
    case OR_I_R0:
      regs[0] |= instr.i;
      print_registers(e, 1, 0);
      break;

    /* or.b imm, #(r0, gbr) */
    case ORB_I_A_R0_GBR: {
      u32 addr = regs[0] + regs[REGISTER_GBR];
      switch (ex->s.step) {
        case 0:
          *ma = stage_ma_read_u8_ex(e, addr);
          print_registers(e, 2, 0, REGISTER_GBR);
          result = STAGE_RESULT_STALL;
          break;

        case 1: {
          /* The value read in the previous access stage is now in the
           * writeback stage; grab it from there. */
          u8 val = ma->v8 | (u8)instr.i;
          *ma = stage_ma_write_u8(e, addr, val);
          print_registers(e, 1, REGISTER_U8, val);
          break;
        }
      }
      break;
    }

    /* rotl rn */
    case ROTL_RN: {
      set_sr_t_if(e, (regs[instr.n] & 0x80000000) != 0);
      regs[instr.n] = (regs[instr.n] << 1) | (regs[instr.n] >> 31);
      print_registers(e, 2, instr.n, REGISTER_T);
      break;
    }

    /* rts */
    case RTS:
      e->state.pc = regs[REGISTER_PR];
      print_registers(e, 1, REGISTER_PC);
      break;

    /* shar rn */
    case SHAR_RN:
      set_sr_t_if(e, (regs[instr.n] & 1) != 0);
      regs[instr.n] = (u32)((s32)regs[instr.n] >> 1);
      print_registers(e, 2, instr.n, REGISTER_T);
      break;

    /* shll rn */
    case SHLL_RN:
      set_sr_t_if(e, (regs[instr.n] & 0x80000000) != 0);
      regs[instr.n] <<= 1;
      print_registers(e, 2, instr.n, REGISTER_T);
      break;

    /* shll2 rn */
    case SHLL2_RN:
      regs[instr.n] <<= 2;
      print_registers(e, 1, instr.n);
      break;

    /* shll8 rn */
    case SHLL8_RN:
      regs[instr.n] <<= 8;
      print_registers(e, 1, instr.n);
      break;

    /* shll16 rn */
    case SHLL16_RN:
      regs[instr.n] <<= 16;
      print_registers(e, 1, instr.n);
      break;

    /* shlr rn */
    case SHLR_RN:
      set_sr_t_if(e, (regs[instr.n] & 1) != 0);
      regs[instr.n] >>= 1;
      print_registers(e, 2, instr.n, REGISTER_T);
      break;

    /* shlr2 rn */
    case SHLR2_RN:
      regs[instr.n] >>= 2;
      print_registers(e, 1, instr.n);
      break;

    /* shlr8 rn */
    case SHLR8_RN:
      regs[instr.n] >>= 8;
      print_registers(e, 1, instr.n);
      break;

    /* stc sr, rn */
    case STC_SR_RN:
      regs[instr.n] = regs[REGISTER_SR];
      print_registers(e, 1, instr.n);
      break;

    /* sts macl, rn */
    case STS_MACL_RN:
      /* TODO(binji): handle multiplier contention. */
      *ma = (StageMA){
          .s = ex->s, .type = MEMORY_ACCESS_READ_MACL, .wb_reg = instr.n};
      break;

    /* sts.l macl, @-rn */
    case STSL_MACL_AMRN:
      /* TODO(binji): handle multiplier contention. */
      regs[instr.n] -= 4;
      *ma = stage_ma_write_u32(e, regs[instr.n], regs[REGISTER_MACL]);
      print_registers(e, 2, REGISTER_MACL, instr.n);
      break;

    /* sts.l pr, @-rn */
    case STSL_PR_AMRN:
      regs[instr.n] -= 4;
      *ma = stage_ma_write_u32(e, regs[instr.n], regs[REGISTER_PR]);
      print_registers(e, 2, REGISTER_PR, instr.n);
      break;

    /* sub rm, rn */
    case SUB_RM_RN:
      regs[instr.n] -= regs[instr.m];
      print_registers(e, 2, instr.m, instr.n);
      break;

    /* swap.w rm, rn */
    case SWAPW_RM_RN:
      regs[instr.n] = (regs[instr.m] << 16) | (regs[instr.m] >> 16);
      print_registers(e, 1, instr.n);
      break;

    /* tst rm, rn */
    case TST_RM_RN:
      set_sr_t_if(e, (regs[instr.n] & regs[instr.m]) == 0);
      print_registers(e, 3, instr.m, instr.n, REGISTER_T);
      break;

    /* tst imm, r0 */
    case TST_I_R0:
      set_sr_t_if(e, (instr.i & regs[0]) == 0);
      print_registers(e, 2, 0, REGISTER_T);
      break;

    /* xtrct rm, rn */
    case XTRCT_RM_RN:
      regs[instr.n] = (regs[instr.m] << 16) | (regs[instr.n] >> 16);
      print_registers(e, 1, instr.n);
      break;

    default:
      result = STAGE_RESULT_UNIMPLEMENTED;
      break;
  }

  if (e->verbosity > 0) {
    printf("\n");
  }

  if (result == STAGE_RESULT_UNIMPLEMENTED) {
    PRINT_ERROR("unimplemented instruction '%s'\n", s_op_info[instr.op].op_str);
    return result;
  }

  ex->s.active = false;

  return result;
}

StageResult stage_memory_access(Emulator* e) {
  StageResult result = STAGE_RESULT_OK;
  StageEX* ex = &e->state.pipeline.ex;
  StageMA* ma = &e->state.pipeline.ma;
  StageMM* mm = &e->state.pipeline.mm;
  StageWB* wb = &e->state.pipeline.wb;

  if (!ma->s.active) {
    return result;
  }

  if (e->verbosity > 1) {
    print_stage(ma->s, "access");
  }

  Address addr = ma->addr;
  u32 val;

#define MA_READ_WB(size)                                      \
  val = SIGN_EXTEND(read_u##size(e, addr), size);             \
  *wb = (StageWB){.s = ma->s, .reg = ma->wb_reg, .val = val}; \
  if (e->verbosity > 1) {                                     \
    printf("[0x%08x] => 0x%08x\n", addr, val);                \
  }

#define MA_READ_EX(size, nibbles)                                 \
  ma->v##size = read_u##size(e, addr);                            \
  ex->s.active = true;                                            \
  ex->s.step++;                                                   \
  if (e->verbosity > 1) {                                         \
    printf("[0x%08x] => 0x%0" #nibbles "x\n", addr, ma->v##size); \
  }                                                               \
  result = STAGE_RESULT_STALL;

#define MA_WRITE(size, nibbles)                               \
  {                                                           \
    u##size val = ma->v##size;                                \
    write_u##size(e, addr, val);                              \
    if (e->verbosity > 1) {                                   \
      printf("  0x%0" #nibbles "x => [0x%08x]\n", val, addr); \
    }                                                         \
  }

  // clang-format off
  switch (e->state.pipeline.ma.type) {
    case MEMORY_ACCESS_READ_U8_WB:  MA_READ_WB(8); break;
    case MEMORY_ACCESS_READ_U16_WB: MA_READ_WB(16); break;
    case MEMORY_ACCESS_READ_U32_WB: MA_READ_WB(32); break;

    case MEMORY_ACCESS_READ_U8_EX:  MA_READ_EX(8, 2); break;
    case MEMORY_ACCESS_READ_U16_EX: MA_READ_EX(16, 4); break;
    case MEMORY_ACCESS_READ_U32_EX: MA_READ_EX(32, 8); break;

    case MEMORY_ACCESS_WRITE_U8: MA_WRITE(8, 2); break;
    case MEMORY_ACCESS_WRITE_U16: MA_WRITE(16, 4); break;
    case MEMORY_ACCESS_WRITE_U32: MA_WRITE(32, 8); break;

    case MEMORY_ACCESS_READ_MACL:
      val = e->state.reg[REGISTER_MACL];
      *wb = (StageWB){.s = ma->s, .reg = ma->wb_reg, .val = val};
      if (e->verbosity > 1) {
        printf("%12s => 0x%08x\n", "MACL", val);
      }
      break;

    case MEMORY_ACCESS_MULTIPLY:
      *mm = (StageMM){.s = ma->s, .mul = ma->mul};
      if (e->verbosity > 1) {
        printf("  (multiply)\n");
      }
      break;
  }
  // clang-format on

#undef MA_READ_WB
#undef MA_READ_EX
#undef MA_WRITE

  /* For now, this will always stall since the IF stage is always active. It's
   * not supposed to stall if the next instruction is already fetched. This
   * happens when fetching instructions from on-chip ROM/cache, so it can fetch
   * two instructions (32-bits) instead of one (16-bits). */
  if (e->state.pipeline.if_.s.active) {
    /* MA and IF contention. */
    result = STAGE_RESULT_STALL;
  }

  ma->s.active = false;

  return result;
}


StageResult stage_multiplier(Emulator* e) {
  StageMM* mm = &e->state.pipeline.mm;

  if (!mm->s.active) {
    return STAGE_RESULT_OK;
  }

  if (e->verbosity > 1) {
    print_stage(mm->s, "multiply");
    printf("%*s", INSTR_COLUMNS, "");
  }

  static const int mul_steps[] = {
    2, /* MULTIPLIER_MULUW */
    2, /* MULTIPLIER_MULSW */
    2, /* MULTIPLIER_MACW */
    4, /* MULTIPLIER_MACL */
    4, /* MULTIPLIER_DMULSL */
    4, /* MULTIPLIER_DMULUL */
    4, /* MULTIPLIER_MULL */
  };

  int steps = mul_steps[mm->mul.type];
  if (++mm->s.step < steps) {
    if (e->verbosity > 1) {
      printf("; processing...");
    }
    mm->s.active = true;
  } else {
    u32* regs = &e->state.reg[0];

    switch (mm->mul.type) {
      case MULTIPLIER_MULU:
        regs[REGISTER_MACL] = mm->mul.rm * mm->mul.rn;
        print_registers(e, 1, REGISTER_MACL);
        break;

      default:
        UNREACHABLE("unexpected multiplier type: %d", mm->mul.type);
        break;
    }

    mm->s.active = false;
  }

  if (e->verbosity > 1) {
    printf("\n");
  }

  return STAGE_RESULT_OK;
}

StageResult stage_writeback(Emulator* e) {
  StageWB* wb = &e->state.pipeline.wb;

  if (!wb->s.active) {
    return STAGE_RESULT_OK;
  }

  wb->s.active = false;

  u32 reg = wb->reg;
  u32 val = wb->val;
  e->state.reg[reg] = val;

  if (e->verbosity > 0) {
    print_stage(wb->s, "writeback");
    printf("%*s; %s:%08x\n", INSTR_COLUMNS, "", s_reg_name[reg], val);
  }

  return STAGE_RESULT_OK;
}

StageResult step(Emulator* e) {
  if (e->verbosity > 1) {
    printf(YELLOW "--- step ---\n" WHITE);
  }
  stage_writeback(e);
  stage_multiplier(e);

  if (stage_memory_access(e) == STAGE_RESULT_STALL) {
    return STAGE_RESULT_STALL;
  }

  switch(stage_execute(e)) {
    case STAGE_RESULT_OK:
      break;
    case STAGE_RESULT_STALL:
      return STAGE_RESULT_STALL;
    case STAGE_RESULT_UNIMPLEMENTED:
      return STAGE_RESULT_UNIMPLEMENTED;
  }

  stage_decode(e);
  stage_fetch(e);

  return STAGE_RESULT_OK;
}

int main(int argc, char** argv) {
  --argc; ++argv;
  int result = 1;
  CHECK_MSG(argc == 1, "no rom file given.\n");
  const char* rom_filename = argv[0];

  Buffer rom;
  CHECK(SUCCESS(read_file(rom_filename, &rom)));
  Emulator* e = malloc(sizeof(Emulator));
  init_emulator(e, &rom);

  e->verbosity = 0;

  StageResult sr;
  int i;
  for (i = 0; i < 1500000; ++i) {
    sr = step(e);

    if (sr == STAGE_RESULT_UNIMPLEMENTED) {
      e->verbosity = 2;
      step(e);
      break;
    }
  }

  free(e);

  return 0;
  ON_ERROR_RETURN;
}
