// $Rev: 17 $ $LastChangedDate: 2009-02-03 09:57:31 +0100 (Wt, 03.02.2009) $
//
// ExcpHook Global ring0 Exception Monitor 
// code by gynvael.coldwind//vx
// mailto: gynvael@coldwind.pl
// www   : http://gynvael.coldwind.pl
//
// LICENSE
// Permission is hereby granted to use, copy, modify, and distribute this
// source code, or portions hereof, for any purpose, without fee, subject
// to the following restrictions:
// 
// 1. The origin of this source code must not be misrepresented.
// 
// 2. Altered versions must be plainly marked as such and must not
//    be misrepresented as being the original source.
// 
// 3. This Copyright notice may not be removed or altered from any
//    source or altered source distribution. 
// 
// This software is provided AS IS. The author does not guarantee that 
// this program works, is bugfree, etc. The author does not take any
// responsibility for eventual damage caused by this program.
// Use at own risk.
//
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <windows.h>
#include <winioctl.h>
#include <psapi.h>
#include <time.h>
#include "config.h"
#include "diStorm/distorm.h"

using namespace std;

//
// PREPROCESSOR STUFF
//

// From DDK
#define KI_EXCEPTION_INTERNAL               0x10000000
#define KI_EXCEPTION_GP_FAULT               (KI_EXCEPTION_INTERNAL | 0x1)
#define KI_EXCEPTION_INVALID_OP             (KI_EXCEPTION_INTERNAL | 0x2)
#define KI_EXCEPTION_INTEGER_DIVIDE_BY_ZERO (KI_EXCEPTION_INTERNAL | 0x3)
#define KI_EXCEPTION_ACCESS_VIOLATION       (KI_EXCEPTION_INTERNAL | 0x4)


//
// GLOBAL VARIABLES
//

// Driver, Service and Device names
const char *ServiceName    = "ExcpHook";
const char *DriverFileName = "ExcpHook.sys";
const char *DeviceName     = "\\\\.\\ExcpHook";

HANDLE dev;


//
// FUNCTION DECLARATIONS
//

// Driver handling
bool LoadDriver();
void UnloadDriver();
bool ExcpHookGetVersion(HANDLE hdev, char *buffer, DWORD size);
DWORD ExcpHookGetStatus(HANDLE hdev);
DWORD ExcpHookGetException(HANDLE hdev, PVOID buffer, DWORD size);

// CTRL-C handling
BOOL CtrlHandler(DWORD fdwCtrlType);

// Destructor
void CleanUp();

// Helper functions
LPCSTR ExceptionCodeToString(DWORD ExceptionCode);
LPCSTR StatusToString(DWORD Status);
void StrToLower(char *ChgMe);
void WriteExceptionInfo(FILE* Dest, DWORD Pid, char *FName, ExceptionInfo *ExcpInfo, bool FirstChance, bool ShowTimestamp);
void ShowHelp();


//
// FUNCTION DEFINITIONS
//

// Function: main
// Params  : int argc    - Argument count
//         : char **argv - Argument array
// Returns : int 0 on success
// Desc    : Main function.
int
main(int argc, char **argv)
{
  // Show banner
  puts("ExcpHook Exception Monitor v" EXCPHOOK_VERSION " by gynvael.coldwind//vx");
  puts("(use -h or --help for help)");

  // Check mutex
  HANDLE Mutex = CreateMutex(NULL, TRUE, "Global\\ExcpHookMutex");
  if(GetLastError() == ERROR_ALREADY_EXISTS || GetLastError() == ERROR_ACCESS_DENIED)
  {
    fprintf(stderr, "Another instance of ExcpHook is already runing.\n"
                    "Only one instance of ExcpHook should run at the time.\n");

    return 1;
  }

  // Parse arguments
  int i;
  char *SeekedSubString = NULL;
  bool ShowTimestamp = false;
  char *LogFileName = NULL;
  bool KnownExceptionsOnly = false;

  for(i = 1; i < argc; i++)
  {
    // What is it ?
    if(strcmp(argv[i], "-h") == 0 ||
       strcmp(argv[i], "--help") == 0)
    {
      // Just show help and exit
      ShowHelp();
      return 0;
    }
    else if(strcmp(argv[i], "-k") == 0)
    {
      // Only known exceptions
      KnownExceptionsOnly = true;
    }
    else if(strcmp(argv[i], "-l") == 0)
    {
      // Get log file name
      i++;
      if(i >= argc)
      {
        // Huh, error
        ShowHelp();
        puts("Missing argument for -l option");
        return 1;
      }
      LogFileName = argv[i];
    }
    else if(strcmp(argv[i], "-t") == 0)
    {
      // Show timestamp
      ShowTimestamp = true;
    }
    else
    {
      // Seeked string
      SeekedSubString = argv[i];
      StrToLower(SeekedSubString);
      printf("Filtering results only to ones containing \"%s\"\n", SeekedSubString);
    }
  }

  // Set CTRL-C handler
  SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE);

  // Load driver
  printf("Loading driver...");
  if(!LoadDriver())
  {
    puts("Driver load failed (sometimes running the app again helps)");
    return 1;
  }

  // Open device
  printf("OK\nOpening device...");
  dev = CreateFile(DeviceName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
  if(dev == INVALID_HANDLE_VALUE)
  {
    // Hmm, some stupid error
    printf("ERROR\n");
  }
  else
  {
    // Request version
    printf("OK\nRequesting info on driver...");
    char ver[256];

    // Get version
    if(ExcpHookGetVersion(dev, ver, 256))
      printf("OK\nDriver: %s\n", ver);
    else
      printf("ERROR\n");

    // Request status
    DWORD Status = ExcpHookGetStatus(dev);
    printf("Driver status: %s\n", StatusToString(Status));

    // Check for error
    if(Status & DRV_STATUS_ERROR)
    {
      // Uh! An error ;<
      puts("Driver error ;<\n");
      CleanUp();
      return 1;
    }

    // Main loop
    printf("Entering loop... press ctrl+c to exit\n\n");

    // Catch exceptions
    for(;;)
    {
      ExceptionInfo ExcpInfo;
      DWORD Ret;

      // Get all exceptions pending
      for(;;)
      {
        // Check the status
        if(ExcpHookGetStatus(dev) == DRV_STATUS_OK_NO_EXCP)
          break;

        // Get exceptions from device

        // Read exception
        Ret = ExcpHookGetException(dev, &ExcpInfo, sizeof(ExcpInfo));
        if(Ret != sizeof(ExcpInfo))
          break;

        // Get Pid and FirstChance
        DWORD AddParams = (DWORD)ExcpInfo.ExcpRecord.ExceptionRecord;
        bool FirstChance = (bool)(!!(AddParams >> 16));
        WORD Pid = (WORD)AddParams;

        // Try to open the process
        char FName[512], LowerFName[512];
        HANDLE Proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD)Pid);

        // Clear arrays
        memset(FName, 0, 512);
        memset(LowerFName, 0, 512);
      
        // Was the open successful ?
        if(Proc)
        {
          GetModuleFileNameEx(Proc, (HMODULE)0, FName, sizeof(FName));
          strcpy(LowerFName, FName);
          StrToLower(LowerFName);
          CloseHandle(Proc);
        }
        else if(KnownExceptionsOnly) // Not successful and KnownExceptionsOnly set ?
        {
          // Well, continue;
          continue;
        }

        // Copy the image name from the excp info
        char FNameFromEprocess[IMAGE_NAME_SIZE+4];
        memcpy(FNameFromEprocess, ExcpInfo.ImageName, IMAGE_NAME_SIZE);
        FNameFromEprocess[IMAGE_NAME_SIZE] = '\0';
        StrToLower(FNameFromEprocess);

        // Does the exception match the SeekedSubString ?
        // Or maybe there is no SeekedSubString ?
        // Or maybe the SeekedSubString is in the image name from EPROCESS ?
        if(!SeekedSubString || strstr(LowerFName, SeekedSubString) || strstr(FNameFromEprocess, SeekedSubString))
        {
          WriteExceptionInfo(stdout, Pid, FName, &ExcpInfo, FirstChance, ShowTimestamp);

          // Should it be written to a file too ?
          if(LogFileName)
          {
            // Yes, write it to log file too
            FILE *f = fopen(LogFileName, "a");
            if(f)
            {
              // Write
              WriteExceptionInfo(f, Pid, FName, &ExcpInfo, FirstChance, ShowTimestamp);
              fclose(f);
            }
            else
            {
              // Error
              puts("Could not open/create log file");              
            }
          }
        }

      }

      // Sleep 100ms
      Sleep(100);
    }
  }

  CleanUp();
  CloseHandle(Mutex);

  return 0;
}

// Function: FileExists
// Params  : const char *Name - Name of the file to check
// Returns : bool true if file exists and is accessible
// Desc    : Checks if the given file exists.
bool
FileExists(const char *Name)
{
  // Get file attributes
  DWORD Status = GetFileAttributes(Name);

  if(Status == INVALID_FILE_ATTRIBUTES)
    return false; // File does not exist or there is no access to it

  if(Status & FILE_ATTRIBUTE_DIRECTORY)
    return false; // File is a directory ^_-

  // File is accessible
  return true;
}


// Function: LoadDriver
// Returns : bool true on success
// Desc    : Loads the driver.
bool
LoadDriver()
{
  SC_HANDLE hSCManager;
  SC_HANDLE hService;
  SERVICE_STATUS ss;
  char path[1024];

  GetCurrentDirectory(sizeof(path), path);
  strcat(path, "\\");
  strcat(path, DriverFileName);

  // Check if the driver exists there
  if(!FileExists(path))
  {
    // Try the path where the exe is
    char total_path[1024], *p;
    GetModuleFileName(GetModuleHandle(0), total_path, sizeof(total_path));
    GetFullPathName(total_path, sizeof(path), path, &p);
    if(p) *p = '\0'; // Rip out the path
    strcat(path, DriverFileName);
    if(!FileExists(path))
    {
      printf("Driver not found!\nIt has to be either in the same directory as the exe or in current dir!\n");
      return false;
    }
  }

  // Open session manager
  hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
  if(!hSCManager)
  {
    puts("OpenSCManager() failed");
    return false;
  }

  // Check for service
  hService = OpenService(hSCManager, ServiceName, SERVICE_START | DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS);
  if(!hService)
  {
    // Try to create
    hService = CreateService(hSCManager, ServiceName, ServiceName,
	SERVICE_START | DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS, SERVICE_KERNEL_DRIVER,
	SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, path,
	NULL, NULL, NULL, NULL, NULL);
    if(!hService)
    {
      puts("CreateService() and OpenService() failed");
      CloseServiceHandle(hSCManager);
      return false;
    }
  }

  QueryServiceStatus(hService, &ss);
  if(ss.dwCurrentState != SERVICE_RUNNING)
  {
    if(!StartService(hService, 0, NULL))
    {
      printf("StartService() failed (%i)\n", (int)GetLastError());
      ControlService(hService, SERVICE_CONTROL_STOP, &ss);
      DeleteService(hService);
      CloseServiceHandle(hService);
      CloseServiceHandle(hSCManager);
      return false;
    }
  }

  CloseServiceHandle(hService);
  CloseServiceHandle(hSCManager);
  
  return true;
}

// Function: UnloadDriver
// Desc    : Unloads the driver.
// TODO: Think about not closing handles to the manager and service in the LoadDriver().
void
UnloadDriver()
{
  SC_HANDLE hSCManager;
  SC_HANDLE hService;
  SERVICE_STATUS ss;

  // Open the service manager
  hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);

  // Open the service
  hService = OpenService(hSCManager, ServiceName, SERVICE_START | DELETE | SERVICE_STOP);

  // Stop and delete the service
  ControlService(hService, SERVICE_CONTROL_STOP, &ss);
  DeleteService(hService);

  // Close handles
  CloseServiceHandle(hService);
  CloseServiceHandle(hSCManager);
} // UnloadDriver

// Function: ExcpHookGetVersion
// Params  : HANDLE hdev    - Device handle
//         : char* buffer   - Buffer to receive the version
//         : DWORD size     - Size of the buffer
// Returns : bool true on success
// Desc    : Gets the driver version. This function is subject to change.
bool 
ExcpHookGetVersion(HANDLE hdev, char *buffer, DWORD size)
{
  DWORD Written;
  bool Ret;

  // Query for driver version
  Ret = (bool)DeviceIoControl(hdev, IOCTL_DRV_QUERY_VERSION, NULL, 0, (PVOID)buffer, size, &Written, NULL);

  // Return
  return Ret;
} // ExcpHookGetVersion


// Function: ExcpHookGetStatus
// Params  : HANDLE hdev    - Device handle
// Returns : DWORD 0xffffffff on fail, status on success.
// Desc    : Gets the device status (see config.h).
DWORD
ExcpHookGetStatus(HANDLE hdev)
{
  DWORD Written;
  DWORD Status;
  bool Ret;

  // Query for driver status
  Ret = (bool)DeviceIoControl(hdev, IOCTL_DRV_QUERY_STATUS, NULL, 0, (PVOID)&Status, sizeof(DWORD), &Written, NULL);

  // All OK ?
  if(!Ret) Status = 0xffffffff;

  // Return
  return Status;
} // ExcpHookGetStatus


// Function: ExcpHookGetStatus
// Params  : HANDLE hdev    - Device handle
// Returns : DWORD 0xffffffff on fail, status on success.
// Desc    : Gets the device status (see config.h).
DWORD 
ExcpHookGetException(HANDLE hdev, PVOID buffer, DWORD size)
{
  bool Ret;
  DWORD Written;

  // Query for exception
  Ret = (bool)DeviceIoControl(hdev, IOCTL_DRV_READ_EXCEPTIONS, NULL, 0, buffer, size, &Written, NULL);

  // All OK ?
  if(!Ret) return 0xffffffff;

  // Return
  return Written;
} // ExcpHookGetException

// Function: CtrlHandler
// Params  : DWORD fdwCtrlType - Event type
// Returns : BOOL FALSE on quit
// Desc    : CTRL+C handler, calls CleanUp().
BOOL
CtrlHandler(DWORD fdwCtrlType) 
{ 
  // What kind of event ?
  switch(fdwCtrlType)
  { 
    case CTRL_C_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
      // Run CleanUp() and quit
      CleanUp();
      return FALSE; 
  } 
  return FALSE;
} // CtrlHandler 

// Function: CleanUp
// Desc    : Cleans up - disconnects from the device and unloads the driver.
void
CleanUp()
{
  // Disconnect from the device
  if(dev)
  {
    printf("Disconnecting from driver...");
    CloseHandle(dev);
    puts("OK");
  }

  // Unload the driver
  printf("Unloading driver...");
  UnloadDriver();
  puts("OK");
}


// Function: ExceptionCodeToString
// Params  : DWORD ExceptionCode - Code of exception
// Returns : LPCSTR Exception name (more like ID)
// Desc    : Translates exception code to a string name.
LPCSTR
ExceptionCodeToString(DWORD ExceptionCode)
{
  // Translate exception code to a proper name
  switch(ExceptionCode)
  {
    case STATUS_SEGMENT_NOTIFICATION:         return "STATUS_SEGMENT_NOTIFICATION";
    case STATUS_GUARD_PAGE_VIOLATION:         return "STATUS_GUARD_PAGE_VIOLATION";
    case STATUS_DATATYPE_MISALIGNMENT:        return "STATUS_DATATYPE_MISALIGNMENT";
    case STATUS_BREAKPOINT:                   return "STATUS_BREAKPOINT";
    case STATUS_SINGLE_STEP:                  return "STATUS_SINGLE_STEP";
    case STATUS_ACCESS_VIOLATION:             return "STATUS_ACCESS_VIOLATION";
    case STATUS_IN_PAGE_ERROR:                return "STATUS_IN_PAGE_ERROR";
    case STATUS_INVALID_HANDLE:               return "STATUS_INVALID_HANDLE";
    case STATUS_NO_MEMORY:                    return "STATUS_NO_MEMORY";
    case STATUS_ILLEGAL_INSTRUCTION:          return "STATUS_ILLEGAL_INSTRUCTION";
    case STATUS_NONCONTINUABLE_EXCEPTION:     return "STATUS_NONCONTINUABLE_EXCEPTION";
    case STATUS_INVALID_DISPOSITION:          return "STATUS_INVALID_DISPOSITION";
    case STATUS_ARRAY_BOUNDS_EXCEEDED:        return "STATUS_ARRAY_BOUNDS_EXCEEDED";
    case STATUS_FLOAT_DENORMAL_OPERAND:       return "STATUS_FLOAT_DENORMAL_OPERAND";
    case STATUS_FLOAT_DIVIDE_BY_ZERO:         return "STATUS_FLOAT_DIVIDE_BY_ZERO";
    case STATUS_FLOAT_INEXACT_RESULT:         return "STATUS_FLOAT_INEXACT_RESULT";
    case STATUS_FLOAT_INVALID_OPERATION:      return "STATUS_FLOAT_INVALID_OPERATION";
    case STATUS_FLOAT_OVERFLOW:               return "STATUS_FLOAT_OVERFLOW";
    case STATUS_FLOAT_STACK_CHECK:            return "STATUS_FLOAT_STACK_CHECK";
    case STATUS_FLOAT_UNDERFLOW:              return "STATUS_FLOAT_UNDERFLOW";
    case STATUS_INTEGER_DIVIDE_BY_ZERO:       return "STATUS_INTEGER_DIVIDE_BY_ZERO";
    case STATUS_INTEGER_OVERFLOW:             return "STATUS_INTEGER_OVERFLOW";
    case STATUS_PRIVILEGED_INSTRUCTION:       return "STATUS_PRIVILEGED_INSTRUCTION";
    case STATUS_STACK_OVERFLOW:               return "STATUS_STACK_OVERFLOW";
    case STATUS_CONTROL_C_EXIT:               return "STATUS_CONTROL_C_EXIT";
    case KI_EXCEPTION_GP_FAULT:               return "KI_EXCEPTION_GP_FAULT";
    case KI_EXCEPTION_INVALID_OP:             return "KI_EXCEPTION_INVALID_OP";
    case KI_EXCEPTION_INTEGER_DIVIDE_BY_ZERO: return "KI_EXCEPTION_INTEGER_DIVIDE_BY_ZERO";
    case KI_EXCEPTION_ACCESS_VIOLATION:       return "KI_EXCEPTION_ACCESS_VIOLATION";
  }

  // Not found ? Huh
  return "UNKNOWN";
} // ExceptionCodeToString


// Function: StatusToString
// Params  : DWORD Status - Status code
// Returns : LPCSTR Status name (more like ID)
// Desc    : Translates status code to a string name.
LPCSTR StatusToString(DWORD Status)
{
  // Translate the status to a proper name
  switch(Status)
  {
    case DRV_STATUS_OK_NO_EXCP:                    return "All OK";
    case DRV_STATUS_OK_EXCP_PENDING:               return "All OK, an exception is pending";
    case DRV_STATUS_OK_EXCP_PENDING_BUFF_FULL:     return "All OK, the exception buffer is full";
    case DRV_STATUS_ERROR_HOOK_FIRST_SIGHT_FAILED: return "Error! First sight failed!";
    case DRV_STATUS_ERROR_HOOK_FIRST_SIGHT_OK:     return "Error! First sight OK, but the signature mismatched!";
    case DRV_STATUS_ERROR_HOOK_FIRST_PATCH_FAILED: return "Error! Patching the kernel failed!";
  }

  // Not found ? Huh
  return "UNKNOWN";
} // StatusToString

// Function: StrToLower
// Params  : char* ChgMe - ASCIIZ string to be changed
// Desc    : Converts the string to be lower case.
void
StrToLower(char *ChgMe)
{
  // Until the string terminator...
  while(*ChgMe)
  {
    // Change upper case into lower case
    if(*ChgMe >= 'A' && *ChgMe <= 'Z') *ChgMe += 'a' - 'A';

    // And move to the next char
    ChgMe++;
  }
} // StrToLower


// Function: ShowHelp
// Desc    : Displays help message.
void
ShowHelp()
{
  puts("usage: ExcpHook [-k] [<Substring>] | [-h | --help]\n"
       "options:\n"
       "  -k            Show only exceptions with known image name\n"
       "  -h or --help  This help screen\n"
       "  <Substring>   Show only exceptions with image names containg given substring\n"
       "  -l <FileName> Log to file\n"
       "  -t            Show timestamp\n");
} // ShowHelp

// Function: WriteExceptionInfo
// Params  : FILE* Dest         - Output stream handle (stdout or some file opened for writing)
//         : DWORD Pid          - Process ID
//         : char* FName        - File name
//         : EXCEPTION_RECORD *ExcpRec - Exception record
//         : bool FirstChange   - First time exception 
//         : bool ShowTimestamp - Is the timestamp to be shown ?
// Desc    : Write information about exception in plain text to a file.
void
WriteExceptionInfo(FILE* Dest, DWORD Pid, char *FName, ExceptionInfo *ExcpInfo, bool FirstChance, bool ShowTimestamp)
{
  // Print exception info
  fprintf(Dest, "--- Exception detected ---\n");

  // Timestamp requided ?
  if(ShowTimestamp)
  {
    time_t CurrTime = time(0);
    fprintf(Dest, "Time: %s", ctime(&CurrTime));
  }

  // Print other info
  fprintf(Dest, "PID: %5u    First Chance: %s\n", Pid, FirstChance ? "YES" : "NO");
  fprintf(Dest, "Exception code: %.8x (%s)\n", 
      ExcpInfo->ExcpRecord.ExceptionCode, 
      ExceptionCodeToString(ExcpInfo->ExcpRecord.ExceptionCode));
  fprintf(Dest, "Exception addr: %.8x\n", ExcpInfo->ExcpRecord.ExceptionAddress);

  // Display the image name if known
  fprintf(Dest, "Image (from OpenProcess): %s\n", *FName ? FName : "<OpenProcess failed>");

  // Display the image according to the driver
  char DrvImageName[IMAGE_NAME_SIZE + 4];
  memcpy(DrvImageName, ExcpInfo->ImageName, IMAGE_NAME_SIZE);
  DrvImageName[IMAGE_NAME_SIZE] = '\0';
  fprintf(Dest, "Image (from EPROCESS)   : %s\n", DrvImageName);

  // Print out parameters
  fprintf(Dest, "Param count   : %i\n", ExcpInfo->ExcpRecord.NumberParameters);

  // Any params ?
  if(ExcpInfo->ExcpRecord.NumberParameters > 0)
  {
    fprintf(Dest, "Params:\n  ");

    // Print params
    DWORD i;
    for(i = 0; i < ExcpInfo->ExcpRecord.NumberParameters && i < EXCEPTION_MAXIMUM_PARAMETERS; i++)
    {
      // Write params
      fprintf(Dest, "%.8x ", ExcpInfo->ExcpRecord.ExceptionInformation[i]);
      if(i != 0 && i % 8 == 0 && i + 1 < ExcpInfo->ExcpRecord.NumberParameters) fprintf(Dest, "\n");
    }
    fprintf(Dest, "\n");
  }

  // Verbose info
  if(ExcpInfo->ExcpRecord.ExceptionCode == KI_EXCEPTION_ACCESS_VIOLATION)
  {
    fprintf(Dest, "Access Violation Type  : %s\n"  , ExcpInfo->ExcpRecord.ExceptionInformation[0] ? "WRITE" : "READ");
    fprintf(Dest, "Accessed Memory Address: %.8x\n", ExcpInfo->ExcpRecord.ExceptionInformation[1]);
  }
  // TODO: Add verbose infomation about other exceptions too.
  
  // General regs
  fprintf(Dest, "Eax: %.8x    Edx: %.8x    Ecx: %.8x    Ebx: %.8x\n", 
      ExcpInfo->Context.Eax,
      ExcpInfo->Context.Edx,
      ExcpInfo->Context.Ecx,
      ExcpInfo->Context.Ebx);

  fprintf(Dest, "Esi: %.8x    Edi: %.8x    Esp: %.8x    Ebp: %.8x\n", 
      ExcpInfo->Context.Esi,
      ExcpInfo->Context.Edi,
      ExcpInfo->Context.Esp,
      ExcpInfo->Context.Ebp);

  // Control regs
  fprintf(Dest, "Eip: %.8x\n", ExcpInfo->Context.Eip);
  fprintf(Dest, "EFlags: %.8x\n", ExcpInfo->Context.EFlags);
  fprintf(Dest, "  CF: %i   PF: %i   AF: %i   ZF: %i   SF: %i   TF: %i\n"
                "  IF: %i   DF: %i   OF: %i   NT: %i   RF: %i   VM: %i\n"
                "  AC: %i   ID: %i\n"
                "  IOPL: %i   VIF: %i   VIP: %i\n",
    !!(ExcpInfo->Context.EFlags & (1 << 0)), // CF
    !!(ExcpInfo->Context.EFlags & (1 << 2)), // PF
    !!(ExcpInfo->Context.EFlags & (1 << 4)), // AF
    !!(ExcpInfo->Context.EFlags & (1 << 6)), // ZF
    !!(ExcpInfo->Context.EFlags & (1 << 7)), // SF
    !!(ExcpInfo->Context.EFlags & (1 << 8)), // TF
    !!(ExcpInfo->Context.EFlags & (1 << 9)), // IF
    !!(ExcpInfo->Context.EFlags & (1 << 10)), // DF
    !!(ExcpInfo->Context.EFlags & (1 << 11)), // OF
    !!(ExcpInfo->Context.EFlags & (1 << 14)), // NT
    !!(ExcpInfo->Context.EFlags & (1 << 16)), // RF
    !!(ExcpInfo->Context.EFlags & (1 << 17)), // VM
    !!(ExcpInfo->Context.EFlags & (1 << 18)), // AC
    !!(ExcpInfo->Context.EFlags & (1 << 21)), // ID
    (ExcpInfo->Context.EFlags & ((1 << 12) | (1 << 13))) >> 12, // IOPL
    !!(ExcpInfo->Context.EFlags & (1 << 19)), // VIF
    !!(ExcpInfo->Context.EFlags & (1 << 20))); // VIP

  // TODO: Add the flags more verblosly

  // Stack
  fprintf(Dest, "\nStack:\n");
  DWORD i;
  DWORD *p = (DWORD*)ExcpInfo->DataAtEsp;
  
  for(i = 0; i < ESP_BUFFER_SIZE / sizeof(void*); i++)
  {
    fprintf(Dest, " %.8x", p[i]);
    if(((i+1) % 8) == 0) fprintf(Dest, "\n");
  }

  fprintf(Dest, "\n");

  // Code
  _DecodeResult res;
  _DecodedInst  inst[16];
  unsigned int  ret;

  res = distorm_decode(ExcpInfo->Context.Eip, ExcpInfo->DataAtEip, EIP_BUFFER_SIZE, Decode32Bits, inst, 16, &ret);

  fprintf(Dest, "Code:\n");
  for(i = 0; i < ret; i++)
  {
    fprintf(Dest, " [%.8x] %-20s %s %s\n",
        (unsigned int)inst[i].offset,
        inst[i].instructionHex.p,
        inst[i].mnemonic.p,
        inst[i].operands.p);
  }


  // Add line separator and flush the stream
  fputs("\n", Dest);
  fflush(Dest);
}
