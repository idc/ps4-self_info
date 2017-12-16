#include "stdafx.h"

#include <llvm/BinaryFormat/ELF.h>
namespace elf = llvm::ELF;

union hilo64_t
{
  uint64_t v;
  struct
  {
    uint32_t lo;
    uint32_t hi;
  };
};

struct self_header
{
  static const uint32_t signature = 0x1D3D154Fu;

  uint32_t magic;
  uint32_t unknown04;
  uint32_t unknown08;
  uint16_t header_size;
  uint16_t unknown0E;
  uint32_t file_size;
  uint32_t unknown14;
  uint16_t segment_count;
  uint16_t unknown1A;
  uint32_t unknown1C;
};

struct self_segment_header
{
  uint32_t flags;
  uint32_t unknown04;
  hilo64_t offset;
  hilo64_t block_table_size;
  hilo64_t uncompressed_size;
};

struct self_info
{
  hilo64_t id;
  hilo64_t unknown08;
  hilo64_t unknown10;
  hilo64_t unknown18;
  uint8_t content_id[32];
};

int main(int argc, char* argv[])
{
  if (argc != 2)
  {
    return 1;
  }

  auto handle = fopen(argv[1], "rb");
  if (handle == nullptr)
  {
    printf("Failed to open file.\n");
    return 2;
  }

  self_header header;
  if (fread(&header, sizeof(self_header), 1, handle) != 1)
  {
    printf("Failed to read SELF header.\n");
    fclose(handle);
    return 3;
  }

  if (header.magic != self_header::signature)
  {
    printf("Not a SELF file.\n");
    fclose(handle);
    return 4;
  }

  auto segment_headers = (self_segment_header*)malloc(sizeof(self_segment_header) * header.segment_count);
  if (fread(segment_headers, sizeof(self_segment_header), header.segment_count, handle) != header.segment_count)
  {
    printf("Failed to read SELF segment headers.\n");
    free(segment_headers);
    fclose(handle);
    return 5;
  }

  uint8_t ident[elf::EI_NIDENT];
  if (fread(ident, sizeof(ident), 1, handle) != 1)
  {
    printf("Failed to read ELF ident.\n");
    free(segment_headers);
    fclose(handle);
    return 6;
  }

  fseek(handle, -static_cast<long>(sizeof(ident)), SEEK_CUR);

  size_t elf_header_size;
  uint16_t program_header_size;
  uint16_t program_count;
  if (ident[elf::EI_CLASS] == 1)
  {
    elf::Elf32_Ehdr elf_header;
    if (fread(&elf_header, sizeof(elf::Elf32_Ehdr), 1, handle) != 1)
    {
      printf("Failed to read ELF header.\n");
      free(segment_headers);
      fclose(handle);
      return 7;
    }
    elf_header_size = sizeof(elf_header);
    program_header_size = elf_header.e_phentsize;
    program_count = elf_header.e_phnum;
  }
  else if (ident[elf::EI_CLASS] == 2)
  {
    elf::Elf64_Ehdr elf_header;
    if (fread(&elf_header, sizeof(elf::Elf64_Ehdr), 1, handle) != 1)
    {
      printf("Failed to read ELF header.\n");
      free(segment_headers);
      fclose(handle);
      return 7;
    }
    elf_header_size = sizeof(elf_header);
    program_header_size = elf_header.e_phentsize;
    program_count = elf_header.e_phnum;
  }
  else
  {
    printf("Unknown ELF class.\n");
    free(segment_headers);
    fclose(handle);
    return 8;
  }

  printf("SELF header:\n");
  printf("  magic ............: %08x\n", header.magic);
  printf("  unknown 04 .......: %08x\n", header.unknown04);
  printf("  unknown 08 .......: %08x\n", header.unknown08);
  printf("  header size ......: %x\n", header.header_size);
  printf("  unknown 0E .......: %x\n", header.unknown0E);
  printf("  file size ........: %x\n", header.file_size);
  printf("  unknown 14 .......: %08x\n", header.unknown14);
  printf("  segment count ....: %u\n", header.segment_count);
  printf("  unknown 1A .......: %04x\n", header.unknown1A);
  printf("  unknown 1C .......: %04x\n", header.unknown1C);
  printf("\n");
  
  printf("SELF segments:\n");

  for (int i = 0; i < header.segment_count; i++)
  {
    auto segment_header = segment_headers[i];
    printf(" [%d]\n", i);
    printf("  flags ............: %08x\n", segment_header.flags);
    printf("  offset ...........: %llx\n", segment_header.offset.v);
    printf("  block table size .: %llx\n", segment_header.block_table_size.v);
    printf("  uncompressed size : %llx\n", segment_header.uncompressed_size.v);
  }
  printf("\n");

  size_t base_header_size = 0;
  base_header_size += sizeof(self_header);
  base_header_size += sizeof(self_segment_header) * header.segment_count;
  base_header_size += elf_header_size;
  base_header_size += program_count * program_header_size;
  base_header_size += 15; base_header_size &= ~15; // align

  if (header.header_size - base_header_size >= sizeof(self_info))
  {
    fseek(handle, static_cast<long>(base_header_size), SEEK_SET);
    self_info info;
    if (fread(&info, sizeof(self_info), 1, handle) == 1)
    {
      printf("SELF info:\n");
      printf("  id ...............: %08x%08x\n", info.id.hi, info.id.lo);
      printf("  unknown 08 .......: %llx\n", info.unknown08.v);
      printf("  unknown 10 .......: %llx\n", info.unknown10.v);
      printf("  unknown 18 .......: %llx\n", info.unknown18.v);
      printf("  content id .......:");
      for (int i = 0; i < 16; i++) printf(" %02x", info.content_id[i]);
      printf("\n");
      printf("                     ");
      for (int i = 0; i < 16; i++) printf(" %02x", info.content_id[16 + i]);
      printf("\n");
      printf("\n");
    }
  }

  free(segment_headers);
  return 0;
}
