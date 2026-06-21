#pragma once

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>

#include <Protocol/DriverSupportedEfiVersion.h>    // For EFI_DRIVER_SUPPORTED_EFI_VERSION_PROTOCOL

// Dummy protocol struct as it is required to install the protocol, but we don't actually use it for anything
typedef struct _DummyProtocolData{
    UINTN blank;
} DummyProtocolData;

extern EFI_GUID  gSingularityDriverProtocolGuid;
extern EFI_GUID  gEfiDriverSupportedEfiVersionProtocolGuid;   // standard EDK2 GUID

extern EFI_DRIVER_SUPPORTED_EFI_VERSION_PROTOCOL  gSingularitySupportedEfiVersion;
extern EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL*         gTextInputEx;
extern DummyProtocolData                          gSingularityDriverProtocol;