#include <Windows.h>
#include <iostream>
#include "../shared.h"

const wchar_t *drv_name = L"ecdsadrv";

// ripped from https://github.com/QCute/WinRing0
static DWORD InstallDriver(SC_HANDLE hSCManager, LPCTSTR DriverId, LPCTSTR DriverPath);
static DWORD RemoveDriver(SC_HANDLE hSCManager, LPCTSTR DriverId);
static DWORD StartDriver(SC_HANDLE hSCManager, LPCTSTR DriverId);
static DWORD StopDriver(SC_HANDLE hSCManager, LPCTSTR DriverId);

DWORD InstallDriver(SC_HANDLE hSCManager, LPCTSTR DriverId, LPCTSTR DriverPath)
{
    DWORD error = NO_ERROR;
    SC_HANDLE hService = CreateService(hSCManager,
					DriverId,
					DriverId,
					SERVICE_ALL_ACCESS,
					SERVICE_KERNEL_DRIVER,
					SERVICE_DEMAND_START,
					SERVICE_ERROR_NORMAL,
					DriverPath,
					NULL,
					NULL,
					NULL,
					NULL,
					NULL
					);

    if (hService == NULL)
    {
	error = GetLastError();
	if(error == ERROR_SERVICE_EXISTS)
	  error = NO_ERROR;
    } else
    {
        CloseServiceHandle(hService);
    }
    return error;
}

DWORD RemoveDriver(SC_HANDLE hSCManager, LPCTSTR DriverId)
{
    DWORD error = NO_ERROR;
    SC_HANDLE hService = OpenService(hSCManager, DriverId, SERVICE_ALL_ACCESS);
    if(hService == NULL)
	error = GetLastError();
    else
    {
 	if (! DeleteService(hService) )
          error = GetLastError();
	CloseServiceHandle(hService);
    }
    return error;
}

DWORD StartDriver(SC_HANDLE hSCManager, LPCTSTR DriverId)
{
    DWORD error = NO_ERROR;
    SC_HANDLE hService = OpenService(hSCManager, DriverId, SERVICE_ALL_ACCESS);

    if(hService != NULL)
    {
	if(! StartService(hService, 0, NULL))
	{
		error = GetLastError();
		if(error == ERROR_SERVICE_ALREADY_RUNNING)
		  error = NO_ERROR;
	}
	CloseServiceHandle(hService);
    } else
      return GetLastError();

    return error;
}

DWORD StopDriver(SC_HANDLE hSCManager, LPCTSTR DriverId)
{
    SERVICE_STATUS	serviceStatus;
    DWORD error = NO_ERROR;

    SC_HANDLE hService = OpenService(hSCManager, DriverId, SERVICE_ALL_ACCESS);

    if(hService != NULL)
    {
	if ( !ControlService(hService, SERVICE_CONTROL_STOP, &serviceStatus) )
	{
	  if ( serviceStatus.dwCurrentState == SERVICE_STOPPED )
            error = NO_ERROR;
	  else
	    error = GetLastError();
	}
        CloseServiceHandle(hService);
    } else
      return GetLastError();

    return error;
}

void usage(const wchar_t *me)
{
  printf("%S: [options]\n", me);
  printf("Options:\n");
  printf(" -u uninstall driver\n");
  printf(" driver_name to install driver\n");
  exit(6);
}

int wmain(int argc, wchar_t **argv)
{
  if ( argc > 2 )
    usage(argv[0]);
  const wchar_t *drv_path = NULL;
  int uninstall = 0;
  if ( argc == 2 )
  {
    if ( !wcscmp(argv[1], L"-u") )
      uninstall = 1;
    else
      drv_path = argv[1];
  }
  // open scmanager
  SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
  if ( NULL == hSCManager )
  {
    printf("cannot OpenSCManager, error %d\n", GetLastError());
    exit(1);
  }
  if ( drv_path != NULL )
  {
    DWORD err = InstallDriver(hSCManager, drv_name, drv_path);
    if ( err != NO_ERROR )
    {
      printf("InstallDriver failed, error %d\n", err);
      CloseServiceHandle(hSCManager);
      return 2;
    }
  } else if ( uninstall )
  {
    StopDriver(hSCManager, drv_name);
    DWORD err = RemoveDriver(hSCManager, drv_name);
    if ( err != NO_ERROR )
    {
      printf("RemoveDriver failed, error %d\n", err);
      CloseServiceHandle(hSCManager);
      return 2;
    }
  } else {
    // test our driver
    DWORD err = StartDriver(hSCManager, drv_name);
    if ( err != NO_ERROR )
    {
      printf("StartDriver failed, error %d\n", err);
      CloseServiceHandle(hSCManager);
      return 2;
    }
    int res = 0;
    ULONG written = 0;
    // open driver
    HANDLE drv = CreateFileW(L"\\\\.\\ecdsadrv",
			GENERIC_READ,
			FILE_SHARE_READ,
			0,                     // Default security
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			0);                    // No template
     if ( drv == INVALID_HANDLE_VALUE )
     {
       printf("cannot open driver, error %d\n", GetLastError());
       goto exit;
     }
     // send IOCTL_TEST_IOCTL
     DeviceIoControl(drv, IOCTL_TEST, NULL, 0, &res, sizeof(res), &written, NULL);
     if ( written != sizeof(res) )
     {
       printf("IOCTL_TEST_IOCTL failed, error %d\n", GetLastError());
     } else {
       printf("IOCTL_TEST_IOCTL return %d\n", res);
       // gather allocation stat
       alloc_stat stat;
       written = 0;
       DeviceIoControl(drv, IOCTL_GET_ECDSA_ALLOCSTAT, NULL, 0, &stat, sizeof(stat), &written, NULL);
       if ( written == sizeof(stat) )
       {
         printf("allocs: %X\n", stat.allocs);
         printf("bad_allocs: %X\n", stat.bad_allocs);
         printf("frees:  %X\n", stat.frees);
       } else
         printf("IOCTL_GET_ECDSA_ALLOCSTAT failed, error %d\n", GetLastError());
     }
exit:
     if ( drv != INVALID_HANDLE_VALUE )
       CloseHandle(drv);
     StopDriver(hSCManager, drv_name);
  }

  CloseServiceHandle(hSCManager);
  return 0;
}
