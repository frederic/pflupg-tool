#include <stdlib.h>
#include <assert.h>
#include <limits.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <libgen.h>
#include <time.h>
#include <gcrypt.h>

#define UPG_HEADER_FLAG_ENCRYPTION	0x20000000
#define UPG_ENTRY_HEADER_ATTR_NESTED	0x04000000

static const char upg_header_magic[] = "2SWU3TXV";

static const char pkey_modulus[] = "010001";
static const char pkey_pubexpo[] = "010001";

typedef struct _struct_sig {
	unsigned char sha1[20];
	unsigned char aes_key[32];
	unsigned char unknown[76];
} struct_sig;

typedef struct _upg_header
{
  unsigned char magic[8];
  uint32_t header_size;
  uint32_t data_size;
  uint32_t crc;
  uint32_t mask;
  uint32_t data_size_decompressed;
  uint32_t padding2;
  unsigned char description[512];
  struct_sig signature;
  unsigned char unknown[32];
  unsigned char releaseStr[28];
} upg_header;

typedef struct _upg_entry_header
{
  char filename[60];
  uint32_t iRealSize;
  uint32_t iStoredSize;
  uint32_t iHeaderSize;
  uint32_t iAttributes;
} upg_entry_header;
