/* $Rev: 17 $ $LastChangedDate: 2009-02-03 09:57:31 +0100 (Wt, 03.02.2009) $
 *
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
 *
 * TODO: DbgPrint should be in a macro
 */
#include <ntddk.h>
#include <windef.h>
#include "../config.h"

// Debug ?
#define DEBUG_ALL_THE_WAY
#ifndef DEBUG_ALL_THE_WAY
#  ifdef DbgPrint
#    undef DbgPrint
#  endif
#  define DbgPrint(a,...)
#endif

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
NTSTATUS ExcpHookDevCtl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS ExcpHookUnsupported(PDEVICE_OBJECT DeviceObject, PIRP Irp);
void DriverUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,PUNICODE_STRING RegistryPath);
PKDPC GainExclusivity(void);
NTSTATUS ReleaseExclusivity(PVOID pkdpc);
VOID RaiseCPUIrqlAndWait(PKDPC Dpc, PVOID DeferredContext, PVOID SysArg1, PVOID SysArg2);
VOID MemoryProtectionOn();
VOID MemoryProtectionOff();

static char sDriverVersion[] = "ExcpHook driver v" EXCPHOOK_VERSION " by gynvael.coldwind//vx.\0\0\0\0"; // zero padded

#pragma alloc_text(INIT, DriverEntry)

// One client only flag
static DWORD bClientConnected;

// Hook variables
unsigned char OrgKiDispatchException_Entry[16];
PVOID OrgKiDispatchException;
DWORD OrgKiDispatchException_SecondPushValue;
DWORD OrgKiDispatchException_JmpAddress;
DWORD OrgKiDispatchException_HookSet;

// Array of information about exceptions
struct ExceptionInfo *ExcpInfo;
DWORD ExcpIdx;
DWORD ExcpMax;

DWORD AllCPURaised, NumberOfRaisedCPU;

// Spin locks
KSPIN_LOCK         SpLock;
KLOCK_QUEUE_HANDLE SpLockQueue;

// Driver status
DWORD DriverStatus;

// XP KTRAP_FRAME structure
// Trap Frame structure made according to WRK-1.0 and struct KTRAP_FRAME
// availible at http://www.nirsoft.net/kernel_struct/vista/KTRAP_FRAME.html
struct XP_KTRAP_FRAME {
  DWORD   DbgEbp;
  DWORD   DbgEip;
  DWORD   DbgArgMark;
  DWORD   DbgArgPointer;
  DWORD   TempSegCs;
  DWORD   TempEsp;
  DWORD   Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
  DWORD   SegGs, SegEs, SegDs;
  DWORD   Edx, Ecx, Eax;
  DWORD   PrevPrevMode;
  PVOID   ExceptionListOrSomething;
  DWORD   SegFs;
  DWORD   Edi, Esi, Ebx, Ebp;
  DWORD   ErrCode;
  DWORD   Eip, SegCs;
  DWORD   EFlags;
  DWORD   HwEsp, HwSegSs;
  DWORD   V86Es, V86Ds, V86Fs, V86Gs;
};

// Some defines used 
#define SEGMENT_MASK    0xffff
#define FRAME_EDITED    0xfff8
#define RPL_MASK     3


/*******************************************************************
 * MySetExceptionInfo()
 *******************************************************************/
void
MySetExceptionInfo(PEXCEPTION_RECORD ExceptionRecord, struct XP_KTRAP_FRAME *TrapFrame, BOOLEAN FirstChance)
{
  DWORD AddParms = (FirstChance << 16) | ((WORD)PsGetCurrentProcessId());
  DWORD Idx;
  DWORD EipFrom, EipTo;
  DWORD EspFrom, EspTo;
  BYTE *EProcess = NULL;

  // Acquire spinlock
  KeAcquireInStackQueuedSpinLock(&SpLock, &SpLockQueue);

  // Can throw in the exception ?
  if(ExcpIdx < ExcpMax)
  {
    // Throw it in
    Idx = ExcpIdx++;

    // Add the data
    RtlCopyMemory(&ExcpInfo[Idx].ExcpRecord, ExceptionRecord, sizeof(*ExceptionRecord));

    // TODO: Move this to a normal place
    ExcpInfo[Idx].ExcpRecord.ExceptionRecord = (PEXCEPTION_RECORD)AddParms;

    // Copy context
    // XXX: Hmm MMX ? FPU ? Debug ?
    ExcpInfo[Idx].Context.ContextFlags = CONTEXT_FULL;

    // Eip / EFlags
    ExcpInfo[Idx].Context.Eip          = TrapFrame->Eip;
    ExcpInfo[Idx].Context.EFlags       = TrapFrame->EFlags;

    // General
    ExcpInfo[Idx].Context.Ebp          = TrapFrame->Ebp;
    ExcpInfo[Idx].Context.Edi          = TrapFrame->Edi;
    ExcpInfo[Idx].Context.Esi          = TrapFrame->Esi;
    ExcpInfo[Idx].Context.Ebx          = TrapFrame->Ebx;
    ExcpInfo[Idx].Context.Ecx          = TrapFrame->Ecx;
    ExcpInfo[Idx].Context.Edx          = TrapFrame->Edx;
    ExcpInfo[Idx].Context.Eax          = TrapFrame->Eax;
    ExcpInfo[Idx].Context.Esp          = TrapFrame->HwEsp;

    // Segment (without cs)
    ExcpInfo[Idx].Context.SegGs        = TrapFrame->SegGs & SEGMENT_MASK;
    ExcpInfo[Idx].Context.SegFs        = TrapFrame->SegFs & SEGMENT_MASK;
    ExcpInfo[Idx].Context.SegEs        = TrapFrame->SegEs & SEGMENT_MASK;
    ExcpInfo[Idx].Context.SegDs        = TrapFrame->SegDs & SEGMENT_MASK;
    ExcpInfo[Idx].Context.SegSs        = TrapFrame->HwSegSs & RPL_MASK;

    // Cs
    if((TrapFrame->SegCs & FRAME_EDITED) == 0)
    {
      ExcpInfo[Idx].Context.SegCs = TrapFrame->TempSegCs & SEGMENT_MASK;
    }
    else
    {
      ExcpInfo[Idx].Context.SegCs = TrapFrame->SegCs & SEGMENT_MASK;
    }

    // XXX: Just check if ESP and EIP are accessible from this point.
    // I'm not so sure about it.

    // Setup
    EipFrom = ExcpInfo[Idx].Context.Eip;
    EipTo   = EipFrom + EIP_BUFFER_SIZE;

    EspFrom = ExcpInfo[Idx].Context.Esp;
    EspTo   = EspFrom + ESP_BUFFER_SIZE;

    RtlZeroMemory(&ExcpInfo[Idx].DataAtEip, EIP_BUFFER_SIZE);
    RtlZeroMemory(&ExcpInfo[Idx].DataAtEsp, ESP_BUFFER_SIZE);
    RtlZeroMemory(&ExcpInfo[Idx].ImageName, IMAGE_NAME_SIZE);

    // Copy EIP[]    
    if(MmIsAddressValid((PVOID)(EipTo-1)) && MmIsAddressValid((PVOID)EipFrom))
    {
      RtlCopyMemory(&ExcpInfo[Idx].DataAtEip, (PVOID)EipFrom, EIP_BUFFER_SIZE);
    }

    // Copy ESP[]
    if(MmIsAddressValid((PVOID)(EspTo-1)) && MmIsAddressValid((PVOID)EspFrom))
    {
      RtlCopyMemory(&ExcpInfo[Idx].DataAtEsp, (PVOID)EspFrom, ESP_BUFFER_SIZE);
    }

    // Copy ImageName from EPROCESS structure
    EProcess = (BYTE*)PsGetCurrentProcess();
    if(EProcess)
    {
      // I thing I can trust PsGetCurrentProcess()
      RtlCopyMemory(&ExcpInfo[Idx].ImageName, &EProcess[OFFSET_IMAGE_NAME], IMAGE_NAME_SIZE);
    }

    // Set the proper status
    DriverStatus = DRV_STATUS_OK_EXCP_PENDING;
  }
  else
  {
    // Set the proper status
    DriverStatus = DRV_STATUS_OK_EXCP_PENDING_BUFF_FULL;
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

    // Stack: ESP -> [FirstChance] [RET] [ExceptionRecord] [ExceptionFrame] [TrapFrame] [PreviousMode] [FirstChance]
    push [esp+0x10] // TrapFrame 

    // Stack: ESP -> [TrapFrame] [FirstChance] [RET] [ExceptionRecord] [ExceptionFrame] [TrapFrame] [PreviousMode] [FirstChance]
    push [esp+0xC]  // ExceptionRecord

    // Call MySetExceptionInfo !
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
  ExFreePoolWithTag((PVOID)ExcpInfo, 'PCXE');
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
  ExcpInfo = (struct ExceptionInfo*)ExAllocatePoolWithTag(NonPagedPool, sizeof(struct ExceptionInfo) * MAX_EXCP_COUNT, 'PCXE');
  if(ExcpInfo == NULL)
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
  DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ExcpHookDevCtl;

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
  KIRQL CurrentIrql, OldIrql;
  PKDPC pkdpc;
  DWORD UnhookOK = 0;
  DbgPrint("ExcpHook: Close\r\n");

  // Acquire spinlock
  KeAcquireInStackQueuedSpinLock(&SpLock, &SpLockQueue);

  // Compare
  if(!bClientConnected)
    return STATUS_UNSUCCESSFUL; // zombie close r evil!

  // Release the spinlock, the rest of the code
  // can be handle without it
  KeReleaseInStackQueuedSpinLock(&SpLockQueue);

  // Unset hook

  DbgPrint("ExcpHook: Trying to unhook\n");

  // Get into dispatch mode
  CurrentIrql = KeGetCurrentIrql();
  OldIrql = CurrentIrql;
  if(CurrentIrql < DISPATCH_LEVEL)
    KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);

  // Gain exclusivity on multicore/multiCPU machines
  pkdpc = GainExclusivity();

  if(OrgKiDispatchException_HookSet)
  {
    __try
    {
      // Turn off memory protection
      MemoryProtectionOff();

      // Patch!
      RtlCopyBytes(OrgKiDispatchException, OrgKiDispatchException_Entry, 16);

      // Turn memory protection back on
      MemoryProtectionOn();

      // Set some flags
      UnhookOK = 1;
      OrgKiDispatchException_HookSet = 0;
    }
    __except(1)
    {
      UnhookOK = 0;
    }
  }

  // Release exclusivity and leave DISPATCH_LEVEL
  ReleaseExclusivity(pkdpc);
  KeLowerIrql(OldIrql);

  // Debug messages
  if(UnhookOK)
    DbgPrint("ExcpHook: Unhooked.\n");
  else  
    DbgPrint("ExcpHook: Unhook failed, expect BSoD\n");

  // Acquire spinlock
  KeAcquireInStackQueuedSpinLock(&SpLock, &SpLockQueue);

  bClientConnected = FALSE;

  // Release the spinlock and return
  KeReleaseInStackQueuedSpinLock(&SpLockQueue);

  return NtStatus;
}

/*******************************************************************
 * ExcpHookCreate()
 * TODO: Split this into 2-3 functions
 *******************************************************************/
NTSTATUS 
ExcpHookCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
  NTSTATUS NtStatus = STATUS_SUCCESS;
  DWORD Addr, EndAddr, i;
  DbgPrint("ExcpHook: Create\r\n");

  // Acquire spinlock
  KeAcquireInStackQueuedSpinLock(&SpLock, &SpLockQueue);

  if(bClientConnected)
    return STATUS_UNSUCCESSFUL; // only one client per time

  bClientConnected = TRUE;

  // Release the spinlock, the rest of the code
  // can be handle without it
  KeReleaseInStackQueuedSpinLock(&SpLockQueue);

  // Set up hook

  // Get kernel start address
  // This previously was done by the following code:
  //   Addr = (DWORD)RtlInitString & 0xfff00000 - 0x10000;
  //   EndAddr = Addr + 0x100000; // 100 pages should be OK
  // And guess what, it BSoD on some kernel versions.
  // (btw thanks to morel of http://idleloop.org/ for reporting the issue!)
  // So now the approach changes to more ring3-find-kernel32.dll-like.
  // I'll take some address, align it to the begining of the page,
  // and seek "MZ" moving backwards (and validating the address ofc).
  // This should give me the begining of the kernel.
  // Then just seek the signature moving foreward.
  Addr = (DWORD)RtlInitString & 0xfffff000;
  __try
  {
    // Find the begining
    while(MmIsAddressValid((PVOID)Addr) &&
          MmIsAddressValid((PVOID)(Addr + 1)) &&
          *(WORD*)Addr != *(WORD*)"MZ") Addr -= 0x1000;
  }
  __except(1)
  {
    // Something failed!
    // Better not continue.
    DbgPrint("ExcpHook: Failed to find kernel start!\r\n");
    bClientConnected = FALSE;
    return STATUS_UNSUCCESSFUL;
  }

  // Double check if the address is valid
  if(!MmIsAddressValid((PVOID)Addr))
  {
    // Something failed!
    // Better not continue.
    DbgPrint("ExcpHook: Found kernel start is invalid!\r\n");
    bClientConnected = FALSE;
    return STATUS_UNSUCCESSFUL;
  }

  // Calc end address
  // This is one of two checks used in the loop
  // The other one is MmIsAddressValid
  EndAddr = Addr + 0x1000 * 0x200; // 512 pages should be OK

  DbgPrint("ExcpHook: Looking for KiDispatchException from %.8x\n", Addr);

  // Preset the status
  DriverStatus = DRV_STATUS_ERROR_HOOK_FIRST_SIGHT_FAILED;

  // Find
  for(;Addr < EndAddr; Addr++)
  {
    // Check if the address is valid
    if(!MmIsAddressValid((PVOID)Addr) ||
       !MmIsAddressValid((PVOID)(Addr + SIG_LENGTH)))
    {
      // Nope, it's the end
      break;
    }

    // Does the sig match ?
    __try
    {
      if(RtlCompareMemory((PVOID)Addr, FuncSig, SIG_FIRST_SIGHT) != SIG_FIRST_SIGHT)
      {
        // Nope, continue
        continue;
      }
    }
    __except(1)
    {
      // Just great, it backfired!
      DbgPrint("ExcpHook: RtlCompareMemory(SIG_FIRST_SIGHT) just threw an exception... bailing out!\n");
      break;
    }

    // This needs some status change
    // Looks like the first site was OK at least once
    DriverStatus = DRV_STATUS_ERROR_HOOK_FIRST_SIGHT_OK;
    DbgPrint("ExcpHook: SIG_FIRST_SIGHT at %.8x\n", Addr);

    // Check the full signature
    __try
    {
      // Setup some flag
      int OK = 1;

      // Masked compare
      for(i = 0; i < SIG_LENGTH; i++)
      {
        if((((unsigned char*)Addr)[i] & FuncMask[i]) != FuncSig[i])
        {
          // Sorry, that's not it
          OK = 0;
          DbgPrint("ExcpHook: Diffrent at %.8x\n", Addr+i);
          break;
        }
      }

      // OK ?
      if(!OK)
      {
        // Nope, still searching
        continue;
      }
    }
    __except(1)
    {
      // Just great, it backfired!
      DbgPrint("ExcpHook: RtlCompareMemory(SIG_LENGTH) just threw an exception... bailing out!\n");
      break;
    }

    // Looks like this is it!
    DbgPrint("ExcpHook: Found KiDispatchException at %.8x, hooking\n", Addr);
    __try
    {
      // Get exclusivity
      KIRQL CurrentIrql, OldIrql;
      PKDPC pkdpc;

      // Get into dispatch mode
      CurrentIrql = KeGetCurrentIrql();
      OldIrql = CurrentIrql;
      if(CurrentIrql < DISPATCH_LEVEL)
        KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);

      // Gain exclusivity on multicore/multiCPU machines
      pkdpc = GainExclusivity();

      // Archive
      OrgKiDispatchException = (PVOID)Addr;
      RtlCopyBytes(OrgKiDispatchException_Entry, (PVOID)Addr, 16);
      RtlCopyBytes(&OrgKiDispatchException_SecondPushValue, (PVOID)(Addr + 6), 4);
      OrgKiDispatchException_JmpAddress = Addr + 10;

      // Setup hook code
      *(DWORD*)(HookCode + 1) = (DWORD)MyKiDispatchException;

      // Turn of memory protection
      MemoryProtectionOff();
        
      // Patch
      RtlCopyBytes((PVOID)Addr, HookCode, 10);

      // Turn it back on
      MemoryProtectionOn();

      // It has been set!
      OrgKiDispatchException_HookSet = 1;

      // Release exclusivity and leave DISPATCH_LEVEL
      ReleaseExclusivity(pkdpc);
      KeLowerIrql(OldIrql);

      // Debug message
      DbgPrint("ExcpHook: Hook set!\n");

      // Set status
      DriverStatus = DRV_STATUS_OK_NO_EXCP;
    } // try
    __except(1)
    {
      // Patch failed
      DriverStatus = DRV_STATUS_ERROR_HOOK_FIRST_PATCH_FAILED;
      DbgPrint("ExcpHook: Hooking failed!\n");
    }

    break;
  } // for

  // Was the hook set ?
  if(!(DriverStatus & DRV_STATUS_OK))
    DbgPrint("ExcpHook: KiDispatchException not found or hook not set!\n");

  // Return
  return NtStatus;
}


/*******************************************************************
 * ExcpHookRead()
 *******************************************************************/
NTSTATUS 
ExcpHookRead(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
  // Some dbg msg
  DbgPrint("ExcpHook: Read (? Don't use Read, use IoCtl)\r\n");

  // Complete the request, but with STATUS_UNSUCCESSFUL status
  Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);

  // Return unsuccessful
  return STATUS_UNSUCCESSFUL;
}

/*******************************************************************
 * ExcpHookWrite()
 *******************************************************************/
NTSTATUS 
ExcpHookWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
  // Some dbg msg
  DbgPrint("ExcpHook: Write (? Don't use Write, use IoCtl)\r\n");

  // Complete the request, but with STATUS_UNSUCCESSFUL status
  Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);

  // Return unsuccessful
  return STATUS_UNSUCCESSFUL;
}

/*******************************************************************
 * ExcpHookDevCtl()
 *******************************************************************/
NTSTATUS 
ExcpHookDevCtl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
  // Some variables
  NTSTATUS NtStatus = STATUS_SUCCESS;
  PIO_STACK_LOCATION pIoStackIrp = NULL;
  PVOID InBuffer, OutBuffer;
  ULONG InBufferSize, OutBufferSize;
  ULONG IOCtlCode;

  // Get current IRP packet location on the stack
  pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);

  // Get params
  InBuffer      = Irp->AssociatedIrp.SystemBuffer;
  InBufferSize  = pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength;
  OutBuffer     = Irp->AssociatedIrp.SystemBuffer;
  OutBufferSize = pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength;
  IOCtlCode     = pIoStackIrp->Parameters.DeviceIoControl.IoControlCode;
  
  /* What is the code ? */
  switch(IOCtlCode)
  {
    /* IOCTL_DRV_QUERY_VERSION */
    case IOCTL_DRV_QUERY_VERSION:
    {
      // Is the size OK ?
      if(OutBufferSize >= sizeof(sDriverVersion))
      {
        // It is OK, copy
        RtlCopyMemory(OutBuffer, sDriverVersion, sizeof(sDriverVersion));

        // Set the information
        Irp->IoStatus.Information = sizeof(sDriverVersion);
      }
      else
      {
        // It is not OK
        NtStatus = STATUS_INFO_LENGTH_MISMATCH;
      }
    }
    break;

    /* IOCTL_DRV_QUERY_STATUS */
    case IOCTL_DRV_QUERY_STATUS:
    {
      // Is the size OK ?
      if(OutBufferSize >= sizeof(DriverStatus))
      {
        // Acquire spinlock
        KeAcquireInStackQueuedSpinLock(&SpLock, &SpLockQueue);

        // It is OK, copy
        *(DWORD*)OutBuffer = DriverStatus;

        // Release the spinlock and return
        KeReleaseInStackQueuedSpinLock(&SpLockQueue); 

        // Set the information
        Irp->IoStatus.Information = sizeof(DriverStatus);
      }
      else
      {
        // It is not OK
        NtStatus = STATUS_INFO_LENGTH_MISMATCH;
      }
    }
    break;

    /* IOCTL_DRV_READ_EXCEPTIONS */
    case IOCTL_DRV_READ_EXCEPTIONS:
    {
      // Count sizes
      DWORD MaxCount = OutBufferSize / sizeof(struct ExceptionInfo);

      // Check output buffer size
      if(OutBufferSize < sizeof(struct ExceptionInfo))
      {
        // Set error and break
        NtStatus = STATUS_INFO_LENGTH_MISMATCH;
        break;
      }

      // Acquire spinlock
      KeAcquireInStackQueuedSpinLock(&SpLock, &SpLockQueue);

      // Check limits
      if(MaxCount > ExcpIdx) MaxCount = ExcpIdx;

      // Can we copy something ?
      if(MaxCount >= 1)
      {
        // Some debug msg
        DbgPrint("ExcpHook: Data count %x %x\n", MaxCount, OutBufferSize);
       
        // Count the data read
        Irp->IoStatus.Information = MaxCount * sizeof(struct ExceptionInfo);

        // Copy the data
        RtlCopyMemory(OutBuffer, ExcpInfo, MaxCount * sizeof(struct ExceptionInfo));

        // Move the data
        ExcpIdx -= MaxCount;

        // Copy
        if(ExcpIdx)
          RtlMoveMemory(ExcpInfo, &ExcpInfo[MaxCount], ExcpIdx * sizeof(struct ExceptionInfo));

      }
      else
      {
        // Nothing transfered, but all OK
        Irp->IoStatus.Information = 0;
      }

      // Release the spinlock
      KeReleaseInStackQueuedSpinLock(&SpLockQueue);

    }
    break;
  }

  // Done
  Irp->IoStatus.Status      = NtStatus;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);

  return NtStatus;
}

/*******************************************************************
 * GainExclusivity()
 * Code from "Rootkits: Subverting the Windows Kernel"
 *  by Greg Hoglund and James Butler
 * This has too run on dispatch level
 *******************************************************************/
PKDPC 
GainExclusivity(void)
{
  NTSTATUS us;
  ULONG u_currentCPU;
  CCHAR i;
  PKDPC pkdpc, temp_pkdpc;

  // Check level
  if(KeGetCurrentIrql() != DISPATCH_LEVEL)
    return NULL;

  // Interlocked zero the globals
  InterlockedAnd(&AllCPURaised, 0);
  InterlockedAnd(&NumberOfRaisedCPU, 0);

  // Setup nonpaged space for DPC functions
  temp_pkdpc = (PKDPC)ExAllocatePool(NonPagedPool, KeNumberProcessors * sizeof(KDPC));
  if(temp_pkdpc == NULL)
    return NULL; // Huh, no mem
  u_currentCPU = KeGetCurrentProcessorNumber();
  pkdpc = temp_pkdpc;

  // XXX: removed '*'
  for(i = 0; i < KeNumberProcessors; i++, temp_pkdpc++)
  {
    // The DPC must not run on the current CPU
    if(i == u_currentCPU) continue;

    KeInitializeDpc(temp_pkdpc, RaiseCPUIrqlAndWait, NULL);
    KeSetTargetProcessorDpc(temp_pkdpc, i);
    KeInsertQueueDpc(temp_pkdpc, NULL, NULL);
  }

  // Wait
  while(InterlockedCompareExchange(&NumberOfRaisedCPU, KeNumberProcessors-1, KeNumberProcessors-1) != KeNumberProcessors-1)
  {
    __asm nop;
  }

  // Return
  return pkdpc;
}

/*******************************************************************
 * ReleaseExclusivity()
 * Code from "Rootkits: Subverting the Windows Kernel"
 *  by Greg Hoglund and James Butler
 *******************************************************************/
NTSTATUS 
ReleaseExclusivity(PVOID pkdpc)
{
  // Inc CPU counter
  InterlockedIncrement(&AllCPURaised);

  // Wait for...
  while(InterlockedCompareExchange(&NumberOfRaisedCPU, 0, 0))
  {
    __asm nop;
  }

  // Free mem
  if(pkdpc != NULL)
  {
    ExFreePool(pkdpc);
    pkdpc = NULL;
  }

  return STATUS_SUCCESS;
}

/*******************************************************************
 * RaiseCPUIrqlAndWait()
 * Code from "Rootkits: Subverting the Windows Kernel"
 *  by Greg Hoglund and James Butler
 *******************************************************************/
VOID 
RaiseCPUIrqlAndWait(PKDPC Dpc, PVOID DeferredContext, PVOID SysArg1, PVOID SysArg2)
{
  InterlockedIncrement(&NumberOfRaisedCPU);
  while(!InterlockedCompareExchange(&AllCPURaised, 1, 1))
  {
    __asm nop;
  }
  InterlockedDecrement(&NumberOfRaisedCPU);
}


/*******************************************************************
 * MemoryProtectionOn()
 * Code from "Rootkits: Subverting the Windows Kernel"
 *  by Greg Hoglund and James Butler
 *******************************************************************/
VOID MemoryProtectionOn()
{
  __asm
  {
    push eax
    mov eax, CR0
    or eax, NOT 0FFFEFFFFh
    mov CR0, eax
    pop eax
  }
}

/*******************************************************************
 * MemoryProtectionOff()
 * Code from "Rootkits: Subverting the Windows Kernel"
 *  by Greg Hoglund and James Butler
 *******************************************************************/
VOID MemoryProtectionOff()
{
  __asm
  {
    push eax
    mov eax, CR0
    and eax, 0FFFEFFFFh
    mov CR0, eax
    pop eax
  }
}

