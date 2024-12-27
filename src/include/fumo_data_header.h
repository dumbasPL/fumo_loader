#pragma once
#include <stdint.h>

#define FUMO_MAGIC 0x4F4D5546 // FUMO
#define FUMO_DATA_VERSION 0x00000002

typedef struct _FUMO_DATA_HEADER {
    uint32_t Magic;
    uint32_t Version;
    uint64_t XorKey;
    uint32_t SettingsSize;
    uint32_t DataSize;
    uint32_t CompressedDataSize;
    uint32_t DecompressedDataSize;
} FUMO_DATA_HEADER, *PFUMO_DATA_HEADER;