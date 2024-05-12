#include <Windows.h>
#include <intrin.h>

typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

u64 VgcBase;

#define NT_SUCCESS(Code) ((Code) >= 0)
#define VGK_IOCTL_HEARTBEAT 0x22C034
#define VGK_IOCTL_INITIALIZED 0x22C050
#define VGC_RC4_KEY_OFFSET 0x0 // put ur offset here
#define VG_RC4_KEY ((u8*)(VgcBase + VGC_RC4_KEY_OFFSET))
#define memcpy(Dst, Src, Len) __movsb((u8*)(Dst), (u8*)(Src), Len)

void RC4_NO_KSA(u8* Key, u8* Input, u32 InputLen) 
{
    u8 S[256];
    u32 a = 0, b = 0;

    memcpy(S, Key, 256);
    for (u32 i = 0; i < InputLen; i++)
    {
        a = (a + 1) % 256;
        b = (b + S[a]) % 256;

        u8 tmp = S[a];
        S[a] = S[b];
        S[b] = tmp;

        Input[i] ^= S[(S[a] + S[b]) % 256];
    }
}

void* OriginalTrampoline;
NTSTATUS NtDeviceIoControlHook(HANDLE hFile, u32 Ioctl, void* Input, u32 InputLen, void* Output, u32 OutputLen)
{
    static bool DoneOnce = false;
    NTSTATUS Orig = decltype(&NtDeviceIoControlHook)(OriginalTrampoline)(hFile, Ioctl, Input, InputLen, Output, OutputLen);
    if (!NT_SUCCESS(Orig))
        return Orig;

    switch (Ioctl)
    {
        case VGK_IOCTL_INITIALIZED:
        {
            // set vgk status to initializer
            // this is done for unload vgk
            RC4_NO_KSA(VG_RC4_KEY, (u8*)Input, InputLen);
            ((u8*)Input)[8] = 1;
            RC4_NO_KSA(VG_RC4_KEY, (u8*)Input, InputLen);
            break;
        }
        case VGK_IOCTL_HEARTBEAT:
        {
            if (DoneOnce)
            {
                CloseHandle(hFile);

                // add code for unload vgk.sys here
                // ......

                // infinite loop in heartbeat thread
                while (true)
                {
                    Sleep(-1);
                }
            }
            else
            {
                // skip first heartbeat
                DoneOnce = true;
            }

            break;
        }
    }

    return Orig;
}

void HookFunction(u64 Addr, void* Hook, void** Orig, u32 OverwriteLen)
{
    u8 TrampolineCode[14] = { 0xFF, 0x25, 0, 0, 0, 0 };

    u8* Trampoline = (u8*)VirtualAlloc(0, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(Trampoline, (void*)Addr, OverwriteLen);
    *(u64*)(&TrampolineCode[6]) = Addr + OverwriteLen;
    memcpy(Trampoline + OverwriteLen, &TrampolineCode[0], sizeof(TrampolineCode));
    *Orig = Trampoline;

    DWORD OldProtect;
    VirtualProtect((void*)Addr, 0x1000, PAGE_EXECUTE_READWRITE, &OldProtect);
    *(void**)&TrampolineCode[6] = Hook;
    memcpy((void*)Addr, &TrampolineCode[0], sizeof(TrampolineCode));
    VirtualProtect((void*)Addr, 0x1000, OldProtect, &OldProtect);
}

bool DllMain(void* ImgBase, DWORD Reason, void* Reserved)
{
    if (Reason != DLL_PROCESS_ATTACH)
        return true;

    VgcBase = (u64)GetModuleHandleA(0);

    HMODULE Ntdll = GetModuleHandleA("ntdll.dll");
    u64 NtDeviceIoControlFile = (u64)GetProcAddress(Ntdll, "NtDeviceIoControlFile");

    HookFunction(NtDeviceIoControlFile, &NtDeviceIoControlHook, &OriginalTrampoline, 15);
    return true;
}