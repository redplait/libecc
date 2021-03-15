#include <ntifs.h>
#include <ntstrsafe.h>
#include "drv_ext.h"
#include "vrfy.h"
#include "shared.h"

VOID ProcessCallback(IN HANDLE  hParentId, IN HANDLE  hProcessId, IN BOOLEAN bCreate);

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
DRIVER_DISPATCH KDispatchCreate;
DRIVER_DISPATCH KDispatchClose;
DRIVER_DISPATCH KDispatchIoctl;

#include "mykeypair_public_key.h"

// allocations pragma
#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#endif /* ALLOC_PRAGMA */

static const PWSTR driver_name     = L"\\Device\\ecdsadrv";
static const PWSTR dos_driver_name = L"\\DosDevices\\ecdsadrv";

UNICODE_STRING gszDriverName;
PDEVICE_OBJECT gpDeviceObject = NULL;

u8 *my_ecc_alloc(u32 size)
{
  return ExAllocatePoolWithTag(PagedPool, size, 'LEcc');
}

void my_ecc_free(u8 *mem)
{
  ExFreePoolWithTag(mem, 'LEcc');
}

void * __fastcall my_dict_alloc(size_t size)
{
  return ExAllocatePoolWithTag(PagedPool, size, 'Dict');
}

void __fastcall my_dict_free(void *mem)
{
  ExFreePoolWithTag(mem, 'Dict');
}

Tdict_alloc g_dict_alloc = my_dict_alloc;
Tdict_free  g_dict_free  = my_dict_free;
Tbuf_alloc g_buf_alloc = my_ecc_alloc;
Tbuf_free g_buf_free = my_ecc_free;

typedef struct _SYSTEM_PERFORMANCE_INFORMATION {
    unsigned char Reserved1[344];
} SYSTEM_PERFORMANCE_INFORMATION, *PSYSTEM_PERFORMANCE_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    IN ULONG   SystemInformationClass,
    OUT PVOID  SystemInformation,
    IN ULONG   Length,
    OUT PULONG ReturnLength
);

int get_random(unsigned char *buf, u16 len)
{
    // SystemPerformanceInformation eq 2
    size_t min_len;
    DWORD olen = 0;
    SYSTEM_PERFORMANCE_INFORMATION info;
    NTSTATUS status = ZwQuerySystemInformation(2, &info, sizeof(info), (PULONG)&olen);
    if ( !NT_SUCCESS(status) )
      return -1;
    memcpy(buf, &info, len);
    return 0;
}

static int cmp2handles(const void *a, const void *b)
{
  HANDLE aa = (HANDLE)a;
  HANDLE bb = (HANDLE)b;
  if ( aa < bb )
    return -1;
  if ( aa > bb )
    return 1;
  return 0;
}

void destroy_ext(PECDSA_DEVICE_EXTENSION ext)
{
  if ( ext->proc_dict != NULL )
  {
    ExDeleteResourceLite(&ext->DataResource);
    dict_free(ext->proc_dict);
    dict_destroy(ext->proc_dict);
    ext->proc_dict = NULL;
  }
}

// process tree functions
int check(PECDSA_DEVICE_EXTENSION ext, HANDLE pid)
{
  dnode_t *node;
  int res = 0;
  // lock
  KeEnterCriticalRegion();
  ExAcquireResourceSharedLite(&ext->DataResource, TRUE);
  // lookup
  node = dict_lookup(ext->proc_dict, pid);
  if ( node != NULL )
    res = (int)dnode_get(node);
  else
    res = -1;
  // unlock
  ExReleaseResourceLite(&ext->DataResource);
  KeLeaveCriticalRegion();
  return res;
}

void remove_pid(PECDSA_DEVICE_EXTENSION ext, HANDLE pid)
{
  dnode_t *node;
  // lock
  KeEnterCriticalRegion();
  ExAcquireResourceExclusiveLite(&ext->DataResource, TRUE);
  // remove
  node = dict_lookup(ext->proc_dict, pid);
  if ( node != NULL )
    dict_delete(ext->proc_dict, node);
  // unlock
  ExReleaseResourceLite(&ext->DataResource);
  KeLeaveCriticalRegion();
}

int add_pid(PECDSA_DEVICE_EXTENSION ext, HANDLE pid, int value)
{
  dnode_t *node;
  int res = 0;
  // lock
  KeEnterCriticalRegion();
  ExAcquireResourceExclusiveLite(&ext->DataResource, TRUE);
  // check
  node = dict_lookup(ext->proc_dict, pid);
  if ( node != NULL )
  {
    dnode_put(node, (void *)value);
    res = 1;
  } else {
    res = dict_alloc_insert(ext->proc_dict, pid, (void *)value);
  }
  // unlock
  ExReleaseResourceLite(&ext->DataResource);
  KeLeaveCriticalRegion();
  return res;
}

VOID ProcessCallback(
        IN HANDLE  hParentId,
        IN HANDLE  hProcessId,
        IN BOOLEAN bCreate
        )
{
  if ( !bCreate )
  {
    PECDSA_DEVICE_EXTENSION ext = NULL;
    // remove this process
    if ( gpDeviceObject == NULL )
       return;
     ext = (PECDSA_DEVICE_EXTENSION)gpDeviceObject->DeviceExtension;
     if ( ext == NULL )
       return;
     remove_pid(ext, hProcessId);
  }
}

//------------------------------------------------------
NTSTATUS KDispatchCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS KDispatchClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information=0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS KDispatchIoctl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
  NTSTATUS              Status = STATUS_UNSUCCESSFUL;
  PIO_STACK_LOCATION    irpStack  = IoGetCurrentIrpStackLocation(Irp);
  PECDSA_DEVICE_EXTENSION ext = (PECDSA_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
  PCHAR pOutputBuffer  = Irp->AssociatedIrp.SystemBuffer;
  KPROCESSOR_MODE    my_mode = ExGetPreviousMode();
  ULONG              dwBytesWritten = 0;
  int res = 0;

  // check if this is authorized process
  if ( my_mode == UserMode )
  {
    HANDLE pid = PsGetCurrentProcessId();
    res = check(ext, pid);
    if ( !res )
    {
      Status = STATUS_ACCESS_DENIED;
      goto end;
    }
    if ( -1 == res )
    {
      // auth required
      PUNICODE_STRING processFileName = NULL;
      OBJECT_ATTRIBUTES objectAttributes;
      HANDLE fileHandle = NULL;
      IO_STATUS_BLOCK iosb;
      Status = SeLocateProcessImageName(PsGetCurrentProcess(), &processFileName);
      if ( !NT_SUCCESS(Status) )
        goto end;
      InitializeObjectAttributes(&objectAttributes, processFileName, OBJ_KERNEL_HANDLE, NULL, NULL);
      Status = ZwCreateFile(&fileHandle, FILE_GENERIC_READ, &objectAttributes,
        &iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
      if ( !NT_SUCCESS(Status) )
        goto end;
      res = VerifyFile(ext, fileHandle, &iosb);
      ZwClose(fileHandle);
      if ( res )
        add_pid(ext, pid, res);
      if ( res < 1 )
      {
        Status = STATUS_ACCESS_DENIED;
        goto end;
      }
    }
  }

  switch(irpStack->Parameters.DeviceIoControl.IoControlCode)
  {
    case IOCTL_TEST_IOCTL:
      if ( (pOutputBuffer == NULL) ||
           (irpStack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(int))
         )
      {
        Status = STATUS_BUFFER_TOO_SMALL;
	break;
      }
      *(int *)pOutputBuffer = res;
      dwBytesWritten = sizeof(int);
     break;

    default:
     Status = STATUS_INVALID_DEVICE_REQUEST;
  }
end:
  Irp->IoStatus.Status = Status;
  Irp->IoStatus.Information = dwBytesWritten;
  IoCompleteRequest( Irp, IO_NO_INCREMENT );
  return Status;
}  

VOID
DriverUnload(
    IN PDRIVER_OBJECT DriverObject
    )
{

    NTSTATUS       Status;
    UNICODE_STRING DosDeviceName;
    RtlInitUnicodeString(&DosDeviceName, dos_driver_name );
    Status = IoDeleteSymbolicLink (&DosDeviceName );
    // remove process ntfy
    PsSetCreateProcessNotifyRoutine(ProcessCallback, TRUE);
    if( DriverObject->DeviceObject )
    {             
       PECDSA_DEVICE_EXTENSION  pExt = (PECDSA_DEVICE_EXTENSION)DriverObject->DeviceObject->DeviceExtension;
       if ( pExt != NULL )
         destroy_ext(pExt);
       IoDeleteDevice(DriverObject->DeviceObject);
    }
}

NTSTATUS
DriverEntry(
    IN PDRIVER_OBJECT  DriverObject,
    IN PUNICODE_STRING RegistryPath )
{
    PECDSA_DEVICE_EXTENSION  pExt = NULL;
    UNICODE_STRING DosDeviceName;
    NTSTATUS       Status = STATUS_SUCCESS;
    const hash_mapping *hm;
    int res;

    RtlInitUnicodeString( &gszDriverName, driver_name);

    Status = IoCreateDevice(
	DriverObject,
        sizeof(ECDSA_DEVICE_EXTENSION),
        &gszDriverName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &gpDeviceObject
  );
  if (!NT_SUCCESS(Status)) 
  {
     DbgPrint("ecdsadrv: ERROR IoCreateDevice ->  \\Device\\ecdsadrv - %08x\n", Status); 
     return Status;
  }
  pExt = (PECDSA_DEVICE_EXTENSION)gpDeviceObject->DeviceExtension;
  Status = ExInitializeResourceLite( &pExt->DataResource );
  if ( !NT_SUCCESS(Status) )
  {
     IoDeleteDevice(gpDeviceObject);
     gpDeviceObject = NULL;
     return Status;
  }
  // init ecdsa data
  pExt->g_sm = get_sig_by_type(ECRDSA);
  if ( pExt->g_sm == NULL )
  {
    Status = STATUS_CRYPTO_SYSTEM_INVALID;
    goto free_res;
  }
  pExt->g_ec_str_p = ec_get_curve_params_by_type(BRAINPOOLP512R1);
  if ( pExt->g_ec_str_p == NULL )
  {
    Status = STATUS_CRYPTO_SYSTEM_INVALID;
    goto free_res;
  }
  hm = get_hash_by_type(SHA3_512);
  if ( hm == NULL )
  {
    Status = STATUS_CRYPTO_SYSTEM_INVALID;
    goto free_res;
  } else
    pExt->g_hash_type = hm->type;
  import_params(&pExt->params, pExt->g_ec_str_p);
  // import public key
  res = ec_pub_key_import_from_buf(&pExt->g_pub_key, &pExt->params, 
     BRAINPOOLP512R1_ECRDSA_public_key + 3, sizeof(BRAINPOOLP512R1_ECRDSA_public_key) - 3, ECRDSA);
  if ( res )
  {
    Status = STATUS_CRYPTO_SYSTEM_INVALID;
    goto free_res;
  }
  // init process dict
  pExt->proc_dict = dict_create(DICTCOUNT_T_MAX, cmp2handles);
  if ( pExt->proc_dict == NULL )
  {
    Status = STATUS_NO_MEMORY;
    goto free_res;
  }
  // register process ntfy
  Status = PsSetCreateProcessNotifyRoutine(ProcessCallback, FALSE);
  if ( !NT_SUCCESS(Status) )
  {
    destroy_ext(pExt);
    IoDeleteDevice(gpDeviceObject);
    gpDeviceObject = NULL;
    return Status;
  }
  // finally make symbolic link
  RtlInitUnicodeString (&DosDeviceName, dos_driver_name );
  Status = IoCreateSymbolicLink(&DosDeviceName, &gszDriverName);
  if( !NT_SUCCESS(Status) ) 
  {
     DbgPrint( "ecdsadrv: ERROR IoCreateSymbolicLink failed - %08x\n", Status); 
     destroy_ext(pExt);
     IoDeleteDevice(gpDeviceObject);
     gpDeviceObject = NULL;
     return Status;
  }
  
  DriverObject->MajorFunction[IRP_MJ_CREATE]         = KDispatchCreate;
  DriverObject->MajorFunction[IRP_MJ_CLOSE]          = KDispatchClose;
  DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = KDispatchIoctl;
  DriverObject->DriverUnload                         = DriverUnload;

  return Status;

free_res:
  ExDeleteResourceLite(&pExt->DataResource);
  IoDeleteDevice(gpDeviceObject);
  gpDeviceObject = NULL;
  return Status;  
}