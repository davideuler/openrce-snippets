// ExcpHook Global ring0 Exception Monitor 
// code by gynvael.coldwind//vx
// mailto: gynvael@coldwind.pl
// www   : http://gynvael.vexillium.org
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
#include <psapi.h>
#include <time.h>
#include "config.h"

using namespace std;

const char *ServiceName    = "ExcpHook";
const char *DriverFileName = "ExcpHook.sys";
const char *DeviceName     = "\\\\.\\ExcpHook";

bool LoadDriver();
void UnloadDriver();

bool ExcpHookGetVersion(HANDLE dev, char *buffer, DWORD size);
BOOL CtrlHandler(DWORD fdwCtrlType);
void CleanUp();

HANDLE dev;

// from DDK
#define KI_EXCEPTION_INTERNAL               0x10000000
#define KI_EXCEPTION_GP_FAULT               (KI_EXCEPTION_INTERNAL | 0x1)
#define KI_EXCEPTION_INVALID_OP             (KI_EXCEPTION_INTERNAL | 0x2)
#define KI_EXCEPTION_INTEGER_DIVIDE_BY_ZERO (KI_EXCEPTION_INTERNAL | 0x3)
#define KI_EXCEPTION_ACCESS_VIOLATION       (KI_EXCEPTION_INTERNAL | 0x4)

const char *ExcpToStr(DWORD code)
{
  switch(code)
  {
    case STATUS_SEGMENT_NOTIFICATION: return "STATUS_SEGMENT_NOTIFICATION";
    case STATUS_GUARD_PAGE_VIOLATION: return "STATUS_GUARD_PAGE_VIOLATION";
    case STATUS_DATATYPE_MISALIGNMENT: return "STATUS_DATATYPE_MISALIGNMENT";
    case STATUS_BREAKPOINT: return "STATUS_BREAKPOINT";
    case STATUS_SINGLE_STEP: return "STATUS_SINGLE_STEP";
    case STATUS_ACCESS_VIOLATION: return "STATUS_ACCESS_VIOLATION";
    case STATUS_IN_PAGE_ERROR: return "STATUS_IN_PAGE_ERROR";
    case STATUS_INVALID_HANDLE: return "STATUS_INVALID_HANDLE";
    case STATUS_NO_MEMORY: return "STATUS_NO_MEMORY";
    case STATUS_ILLEGAL_INSTRUCTION: return "STATUS_ILLEGAL_INSTRUCTION";
    case STATUS_NONCONTINUABLE_EXCEPTION: return "STATUS_NONCONTINUABLE_EXCEPTION";
    case STATUS_INVALID_DISPOSITION: return "STATUS_INVALID_DISPOSITION";
    case STATUS_ARRAY_BOUNDS_EXCEEDED: return "STATUS_ARRAY_BOUNDS_EXCEEDED";
    case STATUS_FLOAT_DENORMAL_OPERAND: return "STATUS_FLOAT_DENORMAL_OPERAND";
    case STATUS_FLOAT_DIVIDE_BY_ZERO: return "STATUS_FLOAT_DIVIDE_BY_ZERO";
    case STATUS_FLOAT_INEXACT_RESULT: return "STATUS_FLOAT_INEXACT_RESULT";
    case STATUS_FLOAT_INVALID_OPERATION: return "STATUS_FLOAT_INVALID_OPERATION";
    case STATUS_FLOAT_OVERFLOW: return "STATUS_FLOAT_OVERFLOW";
    case STATUS_FLOAT_STACK_CHECK: return "STATUS_FLOAT_STACK_CHECK";
    case STATUS_FLOAT_UNDERFLOW: return "STATUS_FLOAT_UNDERFLOW";
    case STATUS_INTEGER_DIVIDE_BY_ZERO: return "STATUS_INTEGER_DIVIDE_BY_ZERO";
    case STATUS_INTEGER_OVERFLOW: return "STATUS_INTEGER_OVERFLOW";
    case STATUS_PRIVILEGED_INSTRUCTION: return "STATUS_PRIVILEGED_INSTRUCTION";
    case STATUS_STACK_OVERFLOW: return "STATUS_STACK_OVERFLOW";
    case STATUS_CONTROL_C_EXIT: return "STATUS_CONTROL_C_EXIT";
    case KI_EXCEPTION_GP_FAULT: return "KI_EXCEPTION_GP_FAULT";
    case KI_EXCEPTION_INVALID_OP: return "KI_EXCEPTION_INVALID_OP";
    case KI_EXCEPTION_INTEGER_DIVIDE_BY_ZERO: return "KI_EXCEPTION_INTEGER_DIVIDE_BY_ZERO";
    case KI_EXCEPTION_ACCESS_VIOLATION: return "KI_EXCEPTION_ACCESS_VIOLATION";
  }

  return "UNKNOWN";
}

void StrToLower(char *ChgMe)
{
  while(*ChgMe)
  {
    if(*ChgMe >= 'A' && *ChgMe <= 'Z') *ChgMe += 'a' - 'A';
    ChgMe++;
  }
}

void ShowHelp()
{
  puts("usage: ExcpHook [-k] [<Substring>] | [-h | --help]\n"
       "options:\n"
       "  -k            Show only exceptions with known image name\n"
       "  -h or --help  This help screen\n"
       "  <Substring>   Show only exceptions with image names containg given substring\n"
       "  -l <FileName> Log to file\n"
       "  -t            Show timestamp\n");
}

void WriteExceptionInfo(FILE* dst, DWORD Pid, char *FName, EXCEPTION_RECORD *ExcpRec, bool FirstChance, bool ShowTimestamp)
{
  // Print exception info
  fprintf(dst, "--- Exception detected ---\n");

 // Timestamp requided ?
  if(ShowTimestamp)
  {
    time_t CurrTime = time(0);
    fprintf(dst, "Time: %s", ctime(&CurrTime));
  }

  // Print other info
  fprintf(dst, "PID: %5u    First Chance: %s\n", Pid, FirstChance ? "YES" : "NO");
  fprintf(dst, "Exception code: %.8x (%s)\n", ExcpRec->ExceptionCode, ExcpToStr(ExcpRec->ExceptionCode));
  fprintf(dst, "Exception addr: %.8x\n", ExcpRec->ExceptionAddress);

  // Is the Image name known?
  if(!*FName)
  {
    fprintf(dst, "Image: UNKNOWN, OpenProcess failed\n");
  }  
  else
  {
    fprintf(dst, "Image: %s\n", FName);
  }

  // Print out parameters
  fprintf(dst, "Param count   : %i\n", ExcpRec->NumberParameters);
  fprintf(dst, "Params:\n  ");

  // Print params
  DWORD i;
  for(i = 0; i < ExcpRec->NumberParameters && i < EXCEPTION_MAXIMUM_PARAMETERS; i++)
  {
    // Write params
    fprintf(dst, "%.8x ", ExcpRec->ExceptionInformation[i]);
    if(i != 0 && i % 8 == 0 && i + 1 < ExcpRec->NumberParameters) fprintf(dst, "\n");
  }
  fprintf(dst, "\n");

  // Verbose info
  if(ExcpRec->ExceptionCode == KI_EXCEPTION_ACCESS_VIOLATION)
  {
    fprintf(dst, "Access Violation Type  : %s\n", ExcpRec->ExceptionInformation[0] ? "WRITE" : "READ");
    fprintf(dst, "Accessed Memory Address: %.8x\n", ExcpRec->ExceptionInformation[1]);
  }

  fputs("\n", dst);
  fflush(dst);
}

int
main(int argc, char **argv)
{
  // Show banner
  puts("ExcpHook Exception Monitor v" EXCPHOOK_VERSION " by gynvael.coldwind//vx");
  puts("(use -h or --help for help)");

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

    // Main loop
    printf("Entering loop... press ctrl+c to exit\n\n");

    // Catch exceptions
    for(;;)
    {
      EXCEPTION_RECORD ExcpRec;
      DWORD Ret;

      // Get all exceptions pending
      for(;;)
      {
        // Get exceptions from device
        ReadFile(dev, &ExcpRec, sizeof(ExcpRec), &Ret, NULL);
        if(Ret != sizeof(ExcpRec))
          break;

        // Get Pid and FirstChance
        DWORD AddParams = (DWORD)ExcpRec.ExceptionRecord;
        bool FirstChance = (bool)(!!(AddParams >> 16));
        WORD Pid = (WORD)AddParams;

        // Try to open the process
        // TODO: Try to do this without opening the process with PROCESS_ALL_ACCESS
        char FName[512], LowerFName[512];
        HANDLE Proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)Pid);

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

        // Does the exception match the SeekedSubString ?
        // Or maybe there is no SeekedSubString ?
        if(!SeekedSubString || strstr(LowerFName, SeekedSubString))
        {
          WriteExceptionInfo(stdout, Pid, FName, &ExcpRec, FirstChance, ShowTimestamp);

          // Should it be written to a file too ?
          if(LogFileName)
          {
            // Yes, write it to log file too
            FILE *f = fopen(LogFileName, "a");
            if(f)
            {
              // Write
              WriteExceptionInfo(f, Pid, FName, &ExcpRec, FirstChance, ShowTimestamp);
              fclose(f);
            }
            else
            {
              // Error
              puts("Could not open/create log file");              
            }
          }
      
        }

        Sleep(250);
      }
    }
  }

  CleanUp();

  return 0;
}

bool FileExists(const char *Name)
{
  // Just open it, stupid hack ;<
  FILE *f = fopen(Name, "rb");
  if(!f) return false;

  fclose(f);
  return true;
}

bool LoadDriver()
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
      puts("StartService() failed");
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

void UnloadDriver()
{
  SC_HANDLE hSCManager;
  SC_HANDLE hService;
  SERVICE_STATUS ss;
  hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
  hService = OpenService(hSCManager, ServiceName, SERVICE_START | DELETE | SERVICE_STOP);
  ControlService(hService, SERVICE_CONTROL_STOP, &ss);
  DeleteService(hService);
  CloseServiceHandle(hService);
  CloseServiceHandle(hSCManager);
}

bool 
ExcpHookGetVersion(HANDLE hdev, char *buffer, DWORD size)
{
  DWORD Command[3];
  DWORD Written;
  DWORD ret;

  Command[0] = 0; // Get Version
  Command[1] = (DWORD)buffer;
  Command[2] = (DWORD)size;

  ret = WriteFile(hdev, Command, sizeof(Command), &Written, 0);
  if(!ret)
    return false;

  return true;
}

BOOL CtrlHandler(DWORD fdwCtrlType) 
{ 
  switch(fdwCtrlType)
  { 
    case CTRL_C_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
      CleanUp();
      return FALSE; 
  } 
  return FALSE;
} 

void CleanUp()
{

  printf("Disconnecting from driver...");
  CloseHandle(dev);
  puts("OK");

  printf("Unloading driver...");
  UnloadDriver();
  puts("OK");
}



