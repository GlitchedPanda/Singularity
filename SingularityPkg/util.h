#pragma once

#include <Uefi.h>

#include <Library/UefiBootServicesTableLib.h>

#define COM1_PORT 0x3F8 // For VMWare Workstation, adjust as needed.

// https://github.com/Mattiwatti/EfiGuard/blob/04fb763465b819f9a280fd4d235c4159afac2d6a/EfiGuardDxe/util.c#L298
INT32
EFIAPI
SetConsoleTextColour(
	IN UINTN TextColour,
	IN BOOLEAN ClearScreen
	)
{
	CONST INT32 OriginalAttribute = gST->ConOut->Mode->Attribute;
	CONST UINTN BackgroundColour = (UINTN)((OriginalAttribute >> 4) & 0x7);

	gST->ConOut->SetAttribute(gST->ConOut, (TextColour | BackgroundColour));
	if (ClearScreen)
		gST->ConOut->ClearScreen(gST->ConOut);

	return OriginalAttribute;
}

VOID SerialPrint(const CHAR8* msg)
{
    UINTN Wait;

    while (*msg) {
        Wait = 0x10000;
        while (--Wait && !(IoRead8(COM1_PORT + 5) & 0x20));

        IoWrite8(COM1_PORT, *msg++);
    }
}

VOID SingularityDebugPrint(const CHAR8* msg)
{
    SerialPrint(msg);

    // UEFI Console requires Unicode
    CHAR16 buffer[512];
    AsciiStrToUnicodeStrS(msg, buffer, sizeof(buffer)/sizeof(CHAR16));

    gST->ConOut->OutputString(gST->ConOut, buffer);
}

VOID SingularityPrintBanner(const CHAR8* msg)
{
    SerialPrint(msg);

    CHAR16 buffer[2048];
    UINTN  Out = 0;

    while (*msg && Out < ARRAY_SIZE(buffer) - 1) {
        UINT8 c = (UINT8)*msg++;

        if (c < 0x80) {
            buffer[Out++] = c;
        } else if ((c & 0xE0) == 0xC0) {
            buffer[Out++] = ((c & 0x1F) << 6) | (*msg++ & 0x3F);
        } else if ((c & 0xF0) == 0xE0) {
            UINT16 cp = (c & 0x0F) << 12;
            cp |= (*msg++ & 0x3F) << 6;
            cp |= (*msg++ & 0x3F);
            buffer[Out++] = cp;
        }
        // 4-byte sequences not needed for box-drawing chars; skip if encountered
    }

    buffer[Out] = L'\0';
    gST->ConOut->OutputString(gST->ConOut, buffer);
}

// Stays safe after ExitBootServices.
static VOID EFIAPI SerialPrintSafe(const CHAR8* fmt, ...)
{
    CHAR8 buf[256];
    VA_LIST args;
    VA_START(args, fmt);
    AsciiVSPrint(buf, sizeof(buf), fmt, args);
    VA_END(args);
    SerialPrint(buf);
}