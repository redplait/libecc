#include <ntifs.h>
#include <ntstrsafe.h>
#include "drv_ext.h"
#include "vrfy.h"

#define FILE_BUFFER_SIZE (2 * PAGE_SIZE)
#define FILE_MAX_SIZE (1024 * 1024 * 1024) // 1 GB
#define ALLOWED_CLIENTS	2
// my allocator methods
#define VRFY_POOL_TAG 'EDSA'

struct vrfy_data
{
  char Buffer[FILE_BUFFER_SIZE];
  struct ec_verify_context vrfy[1]; // variable size
};

const unsigned char whut[] = {
#include "1.inc"
};

const unsigned char whut2[] = {
#include "2.inc"
};

int VerifyFile(PECDSA_DEVICE_EXTENSION pExt, HANDLE fileHandle, IO_STATUS_BLOCK *iosb)
{
  NTSTATUS Status;
  int res = 0;
  int vrfy_idx;
  ULONG remainingBytes;
  ULONG bytesToRead;
  FILE_STANDARD_INFORMATION standardInfo;
  struct vrfy_data *data;
  size_t data_size = sizeof(struct vrfy_data) + sizeof(struct ec_verify_context) * (ALLOWED_CLIENTS - 1);
  Status = ZwQueryInformationFile(fileHandle, iosb, &standardInfo,
        sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
  if ( !NT_SUCCESS(Status) )
    return 0;
  if (standardInfo.EndOfFile.QuadPart <= 0)
    return 0;
  if (standardInfo.EndOfFile.QuadPart > FILE_MAX_SIZE)
    return 0;
  // alloc enough memory
  data = (struct vrfy_data *)ExAllocatePoolWithTag(PagedPool, data_size, VRFY_POOL_TAG);
  if ( data == NULL )
    return 0;
  // init verifiers
  res = ec_verify_init(&data->vrfy[0], &pExt->g_pub_key, whut, (u8)sizeof(whut),
          pExt->g_sm->type, pExt->g_hash_type);
  if ( res )
  {
    res = 0;
    goto end;
  }
  res = ec_verify_init(&data->vrfy[1], &pExt->g_pub_key, whut2, (u8)sizeof(whut2),
          pExt->g_sm->type, pExt->g_hash_type);
  if ( res )
  {
    res = 0;
    goto end;
  }
  res = 0;
  // read file
  remainingBytes = (ULONG)standardInfo.EndOfFile.QuadPart;
  while (remainingBytes != 0)
  {
      bytesToRead = FILE_BUFFER_SIZE;
      if (bytesToRead > remainingBytes)
          bytesToRead = remainingBytes;

      if (!NT_SUCCESS(Status = ZwReadFile(fileHandle, NULL, NULL, NULL, iosb, data->Buffer, bytesToRead,
            NULL, NULL)))
        goto end;
      if ((ULONG)iosb->Information != bytesToRead)
        goto end;
      for ( vrfy_idx = 0; vrfy_idx < ALLOWED_CLIENTS; vrfy_idx++ )
      {
         res = ec_verify_update(&data->vrfy[vrfy_idx], data->Buffer, (u32)bytesToRead);
         if ( res )
         {
           res = 0;
           goto end;
         }
      }
      remainingBytes -= bytesToRead;
  }
  // finalize
  for ( vrfy_idx = 0; vrfy_idx < ALLOWED_CLIENTS; vrfy_idx++ )
  {
    res = ec_verify_finalize(&data->vrfy[vrfy_idx]);
    if ( !res )
    {
      res = 1 + vrfy_idx;
      goto end;
    }
  }
  res = 0;
end:
  if ( data != NULL )
    ExFreePoolWithTag(data, VRFY_POOL_TAG);
  return res;
}