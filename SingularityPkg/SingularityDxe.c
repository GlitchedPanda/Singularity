#include <Uefi.h>

#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/CacheMaintenanceLib.h>
#include <Library/IoLib.h>
#include <Library/UefiLib.h>
#include <Library/PrintLib.h>

#include <Protocol/LoadedImage.h>

#include <Guid/EventGroup.h>

#include "SingularityDxe.h"

#include "util.h"

#define SINGULARITY_TITLE1 "\r\n███████╗██╗███╗   ██╗ ██████╗ ██╗   ██╗██╗      █████╗ ██████╗ ██╗████████╗██╗   ██╗" \
                           "\r\n██╔════╝██║████╗  ██║██╔════╝ ██║   ██║██║     ██╔══██╗██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝" \
                           "\r\n███████╗██║██╔██╗ ██║██║  ███╗██║   ██║██║     ███████║██████╔╝██║   ██║    ╚████╔╝" \
                           "\r\n╚════██║██║██║╚██╗██║██║   ██║██║   ██║██║     ██╔══██║██╔══██╗██║   ██║     ╚██╔╝" \
                           "\r\n███████║██║██║ ╚████║╚██████╔╝╚██████╔╝███████╗██║  ██║██║  ██║██║   ██║      ██║" \
                           "\r\n╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝" 
#define SINGULARITY_TITLE2 "\r\n                                                                                 " \
                           "\r\n                                                                                 " \
                           "\r\n                              Made by GlitchedPanda                              \r\n\n"
                                                                                                

EFI_GUID  gSingularityDriverProtocolGuid = { 
  0xdeadfade, 0x0601, 0x47C6, { 0x84, 0xE7, 0x2E, 0xBC, 0x93, 0x7D, 0x1B, 0x11 }
};

EFI_GUID  gEfiDriverSupportedEfiVersionProtocolGuid = { 
  0xdeadfade, 0xDB2B, 0x42D2, { 0xBF, 0x5F, 0xBA, 0xF9, 0xC5, 0x51, 0x71, 0x54 }
};

EFI_DRIVER_SUPPORTED_EFI_VERSION_PROTOCOL  gSingularitySupportedEfiVersion = { 0 };
EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL          *gTextInputEx = NULL;
DummyProtocolData                          gSingularityDriverProtocol = { 0 };

static EFI_SET_VARIABLE oSetVariable = NULL;

static EFI_EVENT NotifyEvent = NULL;
static EFI_EVENT ExitEvent   = NULL;
static BOOLEAN   Virtual     = FALSE;
static BOOLEAN   Runtime     = FALSE;

// Buffer used as the only legal call target for usermode-issued operations.
static UINTN DriverBuffer = 0;

#define VARIABLE_NAME L"Singularity42"
#define COMMAND_MAGIC 0xDEADFADE
#define DRIVER_SIZE   0x2000000  // 32MB. Should be enough for a full kernel driver, but can be adjusted as needed.

typedef struct _MemoryCommand 
{
    int magic;
    int operation;
    unsigned long long data[10];
    int size;
} MemoryCommand;

typedef UINTN (__stdcall *ExAllocatePool)(int type, UINTN size);
typedef void  (__stdcall *ExFreePool)(UINTN address);
typedef void  (__stdcall *StandardFuncStd)(void);
typedef void  (__fastcall *StandardFuncFast)(void);
typedef unsigned long (__stdcall *DriverEntry)(void* driver, void* registry);

// https://github.com/SamuelTulach/efi-memory/blob/33a9896b7b42725ae9020b354ee3bce59af91976/driver/main.c#L61
EFI_STATUS
RunCommand(MemoryCommand* cmd)
{
    if (cmd->magic != COMMAND_MAGIC) { // Size check is probably not enough on its own
        SerialPrintSafe("SingularityDxe: RunCommand bad magic 0x%x (expected 0x%x)\r\n",
                  cmd->magic, COMMAND_MAGIC);
        return EFI_ACCESS_DENIED;
    }

    SerialPrintSafe("SingularityDxe: RunCommand op=%d size=%d data[0]=0x%lx data[1]=0x%lx\r\n",
              cmd->operation, cmd->size,
              (UINT64)cmd->data[0], (UINT64)cmd->data[1]);

    // 0: memcpy(dst, src, size)
    if (cmd->operation == 0) {
        if (cmd->size <= 0 || cmd->size > 0x1000000) {
            SerialPrintSafe("SingularityDxe: op0 invalid size %d\r\n", cmd->size);
            return EFI_INVALID_PARAMETER;
        }
        if (cmd->data[0] == 0 || cmd->data[1] == 0) {
            SerialPrintSafe("SingularityDxe: op0 null src/dst\r\n");
            return EFI_INVALID_PARAMETER;
        }
        CopyMem((VOID*)(UINTN)cmd->data[0], (VOID*)(UINTN)cmd->data[1], cmd->size);
        SerialPrintSafe("SingularityDxe: op0 copy ok\r\n");
        return EFI_SUCCESS;
    }

    // 1: report DriverBuffer address back to caller via cmd->data[3]
    if (cmd->operation == 1) {
        if (cmd->data[2] == 0 || cmd->data[2] > DRIVER_SIZE) {
            SerialPrintSafe("SingularityDxe: op1 invalid request size %lu\r\n",
                      (UINT64)cmd->data[2]);
            return EFI_INVALID_PARAMETER;
        }
        if (cmd->data[3] != 0) {
            *(UINTN*)(UINTN)cmd->data[3] = DriverBuffer;
            SerialPrintSafe("SingularityDxe: op1 wrote DriverBuffer=0x%lx to 0x%lx\r\n",
                      (UINT64)DriverBuffer, (UINT64)cmd->data[3]);
        } else {
            SerialPrintSafe("SingularityDxe: op1 no output slot provided\r\n");
        }
        return EFI_SUCCESS;
    }

    // 3: call __stdcall void() inside DriverBuffer
    if (cmd->operation == 3) {
        UINTN target = (UINTN)cmd->data[0];
        if (DriverBuffer == 0 || target < DriverBuffer || target >= DriverBuffer + DRIVER_SIZE) {
            SerialPrintSafe("SingularityDxe: op3 target 0x%lx outside DriverBuffer\r\n",
                      (UINT64)target);
            return EFI_ACCESS_DENIED;
        }
        SerialPrintSafe("SingularityDxe: op3 calling stdcall@0x%lx\r\n", (UINT64)target);
        ((StandardFuncStd)target)();
        SerialPrintSafe("SingularityDxe: op3 returned\r\n");
        return EFI_SUCCESS;
    }

    // 4: call __fastcall void() inside DriverBuffer
    if (cmd->operation == 4) {
        UINTN target = (UINTN)cmd->data[0];
        if (DriverBuffer == 0 || target < DriverBuffer || target >= DriverBuffer + DRIVER_SIZE) {
            SerialPrintSafe("SingularityDxe: op4 target 0x%lx outside DriverBuffer\r\n",
                      (UINT64)target);
            return EFI_ACCESS_DENIED;
        }
        SerialPrintSafe("SingularityDxe: op4 calling fastcall@0x%lx\r\n", (UINT64)target);
        ((StandardFuncFast)target)();
        SerialPrintSafe("SingularityDxe: op4 returned\r\n");
        return EFI_SUCCESS;
    }

    // 5: invoke a Windows-style DriverEntry inside DriverBuffer, return its status
    if (cmd->operation == 5) {
        UINTN target = (UINTN)cmd->data[0];
        if (DriverBuffer == 0 || target < DriverBuffer || target >= DriverBuffer + DRIVER_SIZE) {
            SerialPrintSafe("SingularityDxe: op5 target 0x%lx outside DriverBuffer\r\n",
                      (UINT64)target);
            return EFI_ACCESS_DENIED;
        }
        SerialPrintSafe("SingularityDxe: op5 calling DriverEntry@0x%lx\r\n", (UINT64)target);
        unsigned long status = ((DriverEntry)target)(0, 0);
        SerialPrintSafe("SingularityDxe: op5 returned status=0x%x\r\n", (UINT32)status);
        if (cmd->data[1] != 0) {
            *(unsigned long*)(UINTN)cmd->data[1] = status;
        }
        return EFI_SUCCESS;
    }

    SerialPrintSafe("SingularityDxe: unknown op %d\r\n", cmd->operation);
    return EFI_UNSUPPORTED;
}

EFI_STATUS
EFIAPI
HookedSetVariable(
    IN CHAR16    *VariableName,
    IN EFI_GUID  *VendorGuid,
    IN UINT32    Attributes,
    IN UINTN     DataSize,
    IN VOID      *Data
    )
{
    if (Virtual && Runtime) {
        if (VariableName != NULL && VariableName[0] != CHAR_NULL && VendorGuid != NULL) {
            if (StrnCmp(VariableName, VARIABLE_NAME,
                        (sizeof(VARIABLE_NAME) / sizeof(CHAR16)) - 1) == 0) {
                SerialPrintSafe("SingularityDxe: hook matched (DataSize=%lu)\r\n",
                          (UINT64)DataSize);
                if (DataSize == 0 && Data == NULL) {
                    SerialPrintSafe("SingularityDxe: empty payload, ack\r\n");
                    return EFI_SUCCESS;
                }
                if (DataSize == sizeof(MemoryCommand) && Data != NULL) {
                    EFI_STATUS Result = RunCommand((MemoryCommand*)Data);
                    SerialPrintSafe("SingularityDxe: RunCommand returned %r (0x%lx)\r\n",
                              Result, (UINT64)Result);
                    return Result;
                }
                SerialPrintSafe("SingularityDxe: hook matched but bad payload (DataSize=%lu, expected=%lu)\r\n",
                          (UINT64)DataSize, (UINT64)sizeof(MemoryCommand));
            }
        }
    }
    return oSetVariable(VariableName, VendorGuid, Attributes, DataSize, Data);
}

// SetVirtualAddressMap fires once during the boot-to-runtime transition.
// We need to convert our saved oSetVariable pointer and our
// DriverBuffer base (so usermode hands us correct virtual addresses).
VOID
EFIAPI
SetVirtualAddressMapEvent(
    IN EFI_EVENT Event,
    IN VOID*     Context
    )
{
    SerialPrint("SingularityDxe: VirtualAddressChange event fired\r\n");

    if (oSetVariable != NULL) {
        EFI_STATUS s = gRT->ConvertPointer(0, (VOID**)&oSetVariable);
        SerialPrintSafe("SingularityDxe:   oSetVariable converted -> 0x%lx (status 0x%lx)\r\n",
                  (UINT64)(UINTN)oSetVariable, (UINT64)s);
    }
    if (DriverBuffer != 0) {
        VOID *Tmp = (VOID*)DriverBuffer;
        EFI_STATUS s = gRT->ConvertPointer(0, &Tmp);
        DriverBuffer = (UINTN)Tmp;
        SerialPrintSafe("SingularityDxe:   DriverBuffer converted -> 0x%lx (status 0x%lx)\r\n",
                  (UINT64)DriverBuffer, (UINT64)s);
    }

    NotifyEvent = NULL;
    Virtual = TRUE;
    SerialPrint("SingularityDxe: now in virtual address space\r\n");
}

VOID
EFIAPI
ExitBootServicesEvent(
    IN EFI_EVENT Event,
    IN VOID*     Context
    )
{
    SerialPrint("SingularityDxe: ExitBootServices event fired, OS taking over\r\n");
    ExitEvent = NULL;
    Runtime = TRUE;
}

// https://github.com/SamuelTulach/efi-memory/blob/33a9896b7b42725ae9020b354ee3bce59af91976/driver/main.c#L232
VOID*
SetServicePointer(
    IN OUT EFI_TABLE_HEADER *ServiceTableHeader,
    IN OUT VOID **ServiceTableFunction,
    IN VOID *NewFunction
    )
{
    if (ServiceTableFunction == NULL || NewFunction == NULL || *ServiceTableFunction == NULL) {
        return NULL;
    }

    ASSERT(gBS != NULL);
    ASSERT(gBS->CalculateCrc32 != NULL);

    CONST EFI_TPL Tpl = gBS->RaiseTPL(TPL_HIGH_LEVEL);

    VOID* OriginalFunction = *ServiceTableFunction;
    *ServiceTableFunction = NewFunction;

    ServiceTableHeader->CRC32 = 0;
    gBS->CalculateCrc32((UINT8*)ServiceTableHeader, ServiceTableHeader->HeaderSize, &ServiceTableHeader->CRC32);

    gBS->RestoreTPL(Tpl);
    return OriginalFunction;
}

EFI_STATUS
EFIAPI
DxeDriverUnload (
  IN EFI_HANDLE  ImageHandle
  )
{
  return EFI_ACCESS_DENIED; // Not allowing unload for simplicity, but could be implemented if needed
}

EFI_STATUS
EFIAPI
DxeDriverEntry(
    IN EFI_HANDLE        ImageHandle,
    IN EFI_SYSTEM_TABLE  *SystemTable
    )
{
    EFI_STATUS          Status;
    DummyProtocolData   *ExistingProtocol = NULL;
    EFI_LOADED_IMAGE    *LoadedImage      = NULL;
    VOID                *Buf              = NULL;
    INT32               OriginalAttribute = 0;
    CHAR8               AsciiBuffer[256];

    OriginalAttribute = SetConsoleTextColour(EFI_GREEN, TRUE);
    SingularityDebugPrint("\r\n\r\n");
    SingularityPrintBanner(SINGULARITY_TITLE1);
    SingularityDebugPrint(SINGULARITY_TITLE2);
    gST->ConOut->SetAttribute(gST->ConOut, OriginalAttribute);

    SingularityDebugPrint("SingularityDxe: DxeDriverEntry begin\r\n");

    Status = gBS->OpenProtocol(ImageHandle, &gEfiLoadedImageProtocolGuid,
                               (VOID**)&LoadedImage, ImageHandle,
                               NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
    if (EFI_ERROR(Status)) {
        AsciiSPrint(AsciiBuffer, sizeof(AsciiBuffer),
                    "SingularityDxe: OpenProtocol(LoadedImage) failed (%r)\r\n", Status);
        SingularityDebugPrint(AsciiBuffer);
        return Status;
    }
    SingularityDebugPrint("SingularityDxe:   step 1/7 LoadedImage opened\r\n");

    Status = gBS->LocateProtocol(&gSingularityDriverProtocolGuid, NULL, (VOID**)&ExistingProtocol);
    if (Status != EFI_NOT_FOUND) {
        SingularityDebugPrint("SingularityDxe: already loaded\r\n");
        return EFI_ALREADY_STARTED;
    }
    SingularityDebugPrint("SingularityDxe:   step 2/7 no prior instance found\r\n");

    Status = gBS->InstallMultipleProtocolInterfaces(&ImageHandle,
                                                   &gEfiDriverSupportedEfiVersionProtocolGuid,
                                                   &gSingularitySupportedEfiVersion,
                                                   NULL);
    if (EFI_ERROR(Status)) {
        AsciiSPrint(AsciiBuffer, sizeof(AsciiBuffer),
                    "SingularityDxe: install supported-version protocol failed (%r)\r\n", Status);
        SingularityDebugPrint(AsciiBuffer);
        return Status;
    }
    SingularityDebugPrint("SingularityDxe:   step 3/7 supported-version protocol installed\r\n");

    gBS->HandleProtocol(gST->ConsoleInHandle,
                        &gEfiSimpleTextInputExProtocolGuid,
                        (VOID**)&gTextInputEx);

    Status = gBS->InstallProtocolInterface(&ImageHandle,
                                           &gSingularityDriverProtocolGuid,
                                           EFI_NATIVE_INTERFACE,
                                           &gSingularityDriverProtocol);
    if (EFI_ERROR(Status)) {
        AsciiSPrint(AsciiBuffer, sizeof(AsciiBuffer),
                    "SingularityDxe: install driver protocol failed (%r)\r\n", Status);
        SingularityDebugPrint(AsciiBuffer);
        return Status;
    }
    SingularityDebugPrint("SingularityDxe:   step 4/7 driver protocol installed\r\n");

    LoadedImage->Unload = DxeDriverUnload;

    Status = gBS->AllocatePool(EfiRuntimeServicesCode, DRIVER_SIZE, &Buf);
    if (EFI_ERROR(Status) || Buf == NULL) {
        AsciiSPrint(AsciiBuffer, sizeof(AsciiBuffer),
                    "SingularityDxe: AllocatePool failed (%r)\r\n", Status);
        SingularityDebugPrint(AsciiBuffer);
        DriverBuffer = 0;
    } else {
        ZeroMem(Buf, DRIVER_SIZE);
        DriverBuffer = (UINTN)Buf;
        AsciiSPrint(AsciiBuffer, sizeof(AsciiBuffer),
                    "SingularityDxe: DriverBuffer @ 0x%llx\r\n", (UINT64)DriverBuffer);
        SingularityDebugPrint(AsciiBuffer);
    }

    oSetVariable = (EFI_SET_VARIABLE)SetServicePointer((EFI_TABLE_HEADER*)gRT,
                                                      (VOID**)&gRT->SetVariable,
                                                      (VOID*)HookedSetVariable);
    if (oSetVariable == NULL) {
        SingularityDebugPrint("SingularityDxe: failed to hook SetVariable\r\n");
        return EFI_DEVICE_ERROR;
    }
    AsciiSPrint(AsciiBuffer, sizeof(AsciiBuffer),
                "SingularityDxe:   step 5/7 SetVariable hooked (original @ 0x%llx, hook @ 0x%llx)\r\n",
                (UINT64)(UINTN)oSetVariable, (UINT64)(UINTN)HookedSetVariable);
    SingularityDebugPrint(AsciiBuffer);

    Status = gBS->CreateEventEx(EVT_NOTIFY_SIGNAL, TPL_NOTIFY,
                                SetVirtualAddressMapEvent, NULL,
                                &gEfiEventVirtualAddressChangeGuid, &NotifyEvent);
    if (EFI_ERROR(Status)) {
        AsciiSPrint(AsciiBuffer, sizeof(AsciiBuffer),
                    "SingularityDxe: CreateEventEx(VirtualAddressChange) failed (%r)\r\n", Status);
        SingularityDebugPrint(AsciiBuffer);
        return Status;
    }
    SingularityDebugPrint("SingularityDxe:   step 6/7 VirtualAddressChange event registered\r\n");

    Status = gBS->CreateEventEx(EVT_NOTIFY_SIGNAL, TPL_NOTIFY,
                                ExitBootServicesEvent, NULL,
                                &gEfiEventExitBootServicesGuid, &ExitEvent);
    if (EFI_ERROR(Status)) {
        AsciiSPrint(AsciiBuffer, sizeof(AsciiBuffer),
                    "SingularityDxe: CreateEventEx(ExitBootServices) failed (%r)\r\n", Status);
        SingularityDebugPrint(AsciiBuffer);
        return Status;
    }
    SingularityDebugPrint("SingularityDxe:   step 7/7 ExitBootServices event registered\r\n");

    SingularityDebugPrint("SingularityDxe: loaded\r\n");
    return EFI_SUCCESS;
}