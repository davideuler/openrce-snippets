/* 
 * ExcpHook Global ring0 Exception Monitor (KiDispatchException Hooking Driver)
 * code by gynvael.coldwind//vx
 * mailto: gynvael@coldwind.pl
 * www   : http://gynvael.vexillium.org
 *
 * LICENSE
 * Permission is hereby granted to use, copy, modify, and distribute this
 * source code, or portions hereof, for any purpose, without fee, subject
 * to the following restrictions:
 * 
 * 1. The origin of this source code must not be misrepresented.
 * 
 * 2. Altered versions must be plainly marked as such and must not
 *    be misrepresented as being the original source.
 * 
 * 3. This Copyright notice may not be removed or altered from any
 *    source or altered source distribution. 
 * 
 * This software is provided AS IS. The author does not guarantee that 
 * this program works, is bugfree, etc. The author does not take any
 * responsibility for eventual damage caused by this program.
 * Use at own risk.
 *
 *
 * Command list (WRITE):
 * DWORD    Command  
 * 00000000 Get Version     CHAR  Buffer[], DWORD Size
 *
 * Response list (READ):
 * DWORD    Response        Format
 * Exception data
 */
#include <ntddk.h>
#include <windef.h>
#include "../config.h"

// Special thx to Frank Boldewin for german KiDispatchException signature
static const unsigned char *FuncSig =
  "\x68\x90\x03\x00\x00\x68\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xA1"
  "\x00\x00\x00\x00\x89\x45\xE4\x8B\x75\x08\x89\xB5\x14\xFD\xFF\xFF"
  "\x8B\x4D\x0C\x89\x8D\x10\xFD\xFF\xFF\x8B\x5D\x10\x89\x9D\x08\xFD"
  "\xFF\xFF\x00\xA1\x20\x00\x00\x00\xFF\x80\x04\x05\x00\x00\xC7\x85"
  "\x18\xFD";

static const unsigned char *FuncMask =
  "\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\x00\x00\x00\x00\xFF"
  "\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
  "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
  "\xFF\xFF\x00\xFF\xFF\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
  "\xFF\xFF";

#define SIG_LENGTH 66
#define SIG_FIRST_SIGHT 6

// Changed to 128
#define MAX_EXCP_COUNT 128

static unsigned char HookCode[] =
  "\xB8\x44\x33\x22\x11" // mov eax, JUMP
  "\xFF\xE0"             // jmp eax
  "\x90\x90\x90";        // nop padding

NTSTATUS ExcpHookClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS ExcpHookCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS ExcpHookRead(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS ExcpHookWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS ExcpHookUnsupported(PDEVICE_OBJECT DeviceObject, PIRP Irp);
void DriverUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,PUNICODE_STRING RegistryPath);

static char *sDriverVersion = "ExcpHook driver v" EXCPHOOK_VERSION " by gynvael.coldwind//vx.\0\0\0\0"; // zero padded

#pragma alloc_text(INIT, DriverEntry)

static BOOL bClientConnected;

unsigned char OrgKiDispatchException_Entry[16];
PVOID OrgKiDispatchException;
DWORD OrgKiDispatchException_SecondPushValue;
DWORD OrgKiDispatchException_JmpAddress;
DWORD OrgKiDispatchException_HookSet;

PEXCEPTION_RECORD ExcpRecords;
DWORD ExcpIdx;
DWORD ExcpMax;

// Spin locks
KSPIN_LOCK         SpLock;
KLOCK_QUEUE_HANDLE SpLockQueue;

/*******************************************************************
 * MySetExceptionInfo()
 *******************************************************************/
void
MySetExceptionInfo(PEXCEPTION_RECORD ExceptionRecord, BOOLEAN FirstChance)
{
  DWORD AddParms = (FirstChance << 16) | ((WORD)PsGetCurrentProcessId());
  DWORD Idx;

  // Acquire spinlock
  KeAcquireInStackQueuedSpinLock(&SpLock, &SpLockQueue);

  // Can throw in the exception ?
  if(ExcpIdx < ExcpMax)
  {
    // Throw it in
    Idx = ExcpIdx++;

    // Add the data
    memcpy(&ExcpRecords[Idx], ExceptionRecord, sizeof(*ExceptionRecord));
    ExcpRecords[Idx].ExceptionRecord = (PEXCEPTION_RECORD)AddParms;
  }

  // Release the spinlock and return
  KeReleaseInStackQueuedSpinLock(&SpLockQueue); 
}

/*******************************************************************
 * MyKiDispatchException()
 *
 * Original function params:
 *  IN PEXCEPTION_RECORD ExceptionRecord,
 *  IN PVOID ExceptionFrame,
 *  IN PVOID TrapFrame,
 *  IN KPROCESSOR_MODE PreviousMode,
 *  IN BOOLEAN FirstChance
 *******************************************************************/
__declspec(naked) VOID
MyKiDispatchException(VOID)
{
  __asm
  {
    // Stack: ESP -> [RET] [ExceptionRecord] [ExceptionFrame] [TrapFrame] [PreviousMode] [FirstChance]
    cmp [esp+0x10], KernelMode
    je BailOut

    // Push ExceptionRecord and FirstChance back to the stack
    push [esp+0x14] // FirstChance
    push [esp+0x8]  // ExceptionRecord
    mov eax, MySetExceptionInfo
    call eax // STDCALL
 
    // Done
    BailOut:

    // Restore stack
    push 0x390
    push [OrgKiDispatchException_SecondPushValue]

    // Jump
    jmp [OrgKiDispatchException_JmpAddress]
  }
}

/*******************************************************************
 * HandleGetVersion()
 *******************************************************************/
NTSTATUS HandleGetVersion(char *Ptr, DWORD Size)
{
  NTSTATUS NtStatus = STATUS_SUCCESS;

  // Calculate items requiers
  DWORD StrSize = strlen(sDriverVersion) + 1;

  if(StrSize <= Size) 
  {
    RtlCopyMemory(Ptr, sDriverVersion, StrSize);
  }
  else
  {
    NtStatus = STATUS_UNSUCCESSFUL;
  }

  return NtStatus;
}

/*******************************************************************
 * DriverUnload()
 *******************************************************************/
void
DriverUnload(
  IN PDRIVER_OBJECT DriverObject
  )
{
  UNICODE_STRING usDosDeviceName;

  // Show some debug message
  DbgPrint("ExcpHook: Driver Unload\r\n");

  // Aquire a spinlock
  KeAcquireInStackQueuedSpinLock(&SpLock, &SpLockQueue);

  // Free data list
  ExFreePoolWithTag((PVOID)ExcpRecords, 'PCXE');
  ExcpMax = 0;
  ExcpIdx = 0;

  // Release the spinlock
  KeReleaseInStackQueuedSpinLock(&SpLockQueue); 

  // Remove device
  RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\ExcpHook");
  IoDeleteSymbolicLink(&usDosDeviceName);
  IoDeleteDevice(DriverObject->DeviceObject);

  // Show some debug message
  DbgPrint("ExcpHook: Driver Unload completed\r\n");
}

/*******************************************************************
 * DriverEntry()
 *******************************************************************/
NTSTATUS
DriverEntry(
  IN PDRIVER_OBJECT DriverObject,
  IN PUNICODE_STRING RegistryPath
  )
{
  NTSTATUS NtStatus = STATUS_SUCCESS;
  UNICODE_STRING usDriverName, usDosDeviceName;
  PDEVICE_OBJECT pDeviceObject = NULL;
  UINT i;

  // Some debug message
  DbgPrint("ExcpHook: Driver Entry\r\n");

  // Try to allocate the memory first
  ExcpRecords = (PEXCEPTION_RECORD)ExAllocatePoolWithTag(NonPagedPool, sizeof(EXCEPTION_RECORD) * MAX_EXCP_COUNT, 'PCXE');
  if(ExcpRecords == NULL)
  {
    // Hmm, no memory, no fun
    return STATUS_UNSUCCESSFUL;
  }

  // Set the ExcpMax
  ExcpMax = MAX_EXCP_COUNT;

  // Initialise spinlocks
  KeInitializeSpinLock(&SpLock);

  // Create a device
  RtlInitUnicodeString(&usDriverName, L"\\Device\\ExcpHook");
  RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\ExcpHook");

  NtStatus = IoCreateDevice(DriverObject, 0, &usDriverName, 
      FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
  
  // Set Functions
  for(i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
    DriverObject->MajorFunction[i] = ExcpHookUnsupported;

  DriverObject->MajorFunction[IRP_MJ_CLOSE]  = ExcpHookClose;
  DriverObject->MajorFunction[IRP_MJ_CREATE] = ExcpHookCreate;
  DriverObject->MajorFunction[IRP_MJ_READ]   = ExcpHookRead;
  DriverObject->MajorFunction[IRP_MJ_WRITE]  = ExcpHookWrite;

  DriverObject->DriverUnload = DriverUnload;

  pDeviceObject->Flags |= DO_DIRECT_IO;
  pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

  // Create a symbolic link
  IoCreateSymbolicLink(&usDosDeviceName, &usDriverName);
  
  // Reset the bClientConnected
  bClientConnected = FALSE;
 
  // And another debug msg
  DbgPrint("ExcpHook: Driver Entry completed\r\n");

  return NtStatus;
}

/*******************************************************************
 * ExcpHookUnsupported()
 *******************************************************************/
NTSTATUS 
ExcpHookUnsupported(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
  DbgPrint("ExcpHook: Unsupporeted\r\n");
  return STATUS_NOT_SUPPORTED;
}

/*******************************************************************
 * ExcpHookClose()
 *******************************************************************/
NTSTATUS 
ExcpHookClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
  NTSTATUS NtStatus = STATUS_SUCCESS;
  DbgPrint("ExcpHook: Close\r\n");

  if(!bClientConnected)
    return STATUS_UNSUCCESSFUL; // zombie close r evil!

  bClientConnected = FALSE;

  // Unset hook
  if(OrgKiDispatchException_HookSet)
  {
    DbgPrint("ExcpHook: Trying to unhook\n");
    __try
    {
      memcpy(OrgKiDispatchException, OrgKiDispatchException_Entry, 16);
      DbgPrint("ExcpHook: Unhooked.\n");
      OrgKiDispatchException_HookSet = 0;
    }
    __except(1)
    {
      DbgPrint("ExcpHook: Unhook failed, expect BSoD\n");
    }
  }

  return NtStatus;
}

/*******************************************************************
 * ExcpHookCreate()
 *******************************************************************/
NTSTATUS 
ExcpHookCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
  NTSTATUS NtStatus = STATUS_SUCCESS;
  DWORD Addr, EndAddr, i;
  DbgPrint("ExcpHook: Create\r\n");

  if(bClientConnected)
    return STATUS_UNSUCCESSFUL; // only one client per time

  bClientConnected = TRUE;

  // Set up hook
  Addr = (DWORD)RtlInitString & 0xfff00000 - 0x10000;
  EndAddr = Addr + 0x100000; // 100 pages should be OK

  DbgPrint("ExcpHook: Looking for KiDispatchException from %.8x\n", Addr);

  // Find
  for(;Addr < EndAddr; Addr++)
  {
    // Check first sight
    if(memcmp((PVOID)Addr, FuncSig, SIG_FIRST_SIGHT) == 0)
    {
      // Double check with whole sig
      int OK = 1;
      DbgPrint("ExcpHook: SIG_FIRST_SIGHT at %.8x\n", Addr);
      for(i = 0; i < SIG_LENGTH; i++)
        if((((unsigned char*)Addr)[i] & FuncMask[i]) != FuncSig[i])
        {
          OK = 0;
          DbgPrint("ExcpHook: Diffrent at %.8x\n", Addr+i);
          break;
        }

      if(!OK) continue;

      // Address is OK, hook!
      DbgPrint("ExcpHook: Found KiDispatchException at %.8x, hooking\n", Addr);
      __try
      {
        OrgKiDispatchException = (PVOID)Addr;
        memcpy(OrgKiDispatchException_Entry, (PVOID)Addr, 16);
        memcpy(&OrgKiDispatchException_SecondPushValue, (PVOID)(Addr + 6), 4);
        OrgKiDispatchException_JmpAddress = Addr + 10;

        *(DWORD*)(HookCode + 1) = (DWORD)MyKiDispatchException;

        memcpy((PVOID)Addr, HookCode, 10);

        OrgKiDispatchException_HookSet = 1;
        DbgPrint("ExcpHook: Hook set!\n");      
      }
      __except(1)
      {
        DbgPrint("ExcpHook: Hooking faild!\n");
      }

      break;
    }
  }

  if(Addr >= EndAddr)
  {
    DbgPrint("ExcpHook: KiDispatchException not found (huh?)\n");
  }



  return NtStatus;
}


/*******************************************************************
 * ExcpHookRead()
 *******************************************************************/
NTSTATUS 
ExcpHookRead(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
  NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;
  void *pReadDataBuffer;
  UINT dwDataRead = 0;
  DWORD i, Written;
  PIO_STACK_LOCATION pIoStackIrp = NULL;
//  DbgPrint("ExcpHook: Read\r\n");
  pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);

  if(pIoStackIrp && Irp->MdlAddress)
  {
    pReadDataBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

    if(pReadDataBuffer)
    {
      DWORD MaxCount = pIoStackIrp->Parameters.Read.Length / sizeof(EXCEPTION_RECORD);
      dwDataRead = 0;

      // Acquire spinlock to access the data
      KeAcquireInStackQueuedSpinLock(&SpLock, &SpLockQueue);

      // Check limits
      if(MaxCount > ExcpIdx) MaxCount = ExcpIdx;

      // Can we copy something ?
      if(MaxCount >= 1)
      {
        // DbgPrint("ExcpHook: Data count %x\n", MaxCount);
                
        // Count the data read
        dwDataRead = MaxCount * sizeof(EXCEPTION_RECORD);

        // Copy the data
        memcpy(pReadDataBuffer, ExcpRecords, MaxCount * sizeof(EXCEPTION_RECORD));

        // Move the data
        ExcpIdx -= MaxCount;

        if(ExcpIdx)
          memmove(ExcpRecords, &ExcpRecords[MaxCount], ExcpIdx * sizeof(EXCEPTION_RECORD));
        
      }

      // Release the spinlock
      KeReleaseInStackQueuedSpinLock(&SpLockQueue); 


      NtStatus = STATUS_SUCCESS;
     // DbgPrint("ExcpHook: Read complete %x\r\n", dwDataRead);
    }
  }

  Irp->IoStatus.Status = NtStatus;
  Irp->IoStatus.Information = dwDataRead;

  IoCompleteRequest(Irp, IO_NO_INCREMENT);
 
  return NtStatus;
}

/*******************************************************************
 * ExcpHookWrite()
 *******************************************************************/
#define INVOKE(a,b) if(i+a < DataSize) { b; i+=a; }
#define ARG(a)  (Data[i+a+1])
NTSTATUS 
ExcpHookWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
  NTSTATUS NtStatus = STATUS_SUCCESS;
  PIO_STACK_LOCATION pIoStackIrp = NULL;
  DWORD DataSize, *Data, i;
  void *pWriteDataBuffer;
  pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);
  
  DbgPrint("ExcpHook: Write\r\n");

  if(pIoStackIrp && Irp->MdlAddress && pIoStackIrp->Parameters.Write.Length >= 4)
  {
    pWriteDataBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

    if(pWriteDataBuffer)
    {
      DataSize = pIoStackIrp->Parameters.Write.Length / 4;
      Data = (DWORD*)pWriteDataBuffer;
      for(i = 0; i < DataSize; i++)
      {
        switch(Data[i])
        {
          case 0x00000000:
            INVOKE(2, NtStatus = HandleGetVersion((char*)ARG(0), ARG(1)));
            break;

          default: NtStatus = STATUS_UNSUCCESSFUL;
        }
      }
      DbgPrint("ExcpHook: Write complete\r\n");
    }
  }

  Irp->IoStatus.Status = NtStatus;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);

  return NtStatus;
}


