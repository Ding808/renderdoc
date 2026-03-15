/******************************************************************************
 * The MIT License (MIT)
 *
 * Copyright (c) 2015-2026 Baldur Karlsson
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 ******************************************************************************/

// Stealth hooks: hide RenderDoc from the captured application when
// CaptureOptions::hideFromApplication is enabled.
//
// Hooks provided:
//   - IsDebuggerPresent              - returns FALSE
//   - CheckRemoteDebuggerPresent     - sets *pbDebuggerPresent = FALSE for current process
//   - Module32FirstW / Module32NextW - skip our own DLL from the enumeration
//   - Module32First  / Module32Next  - skip our own DLL from the enumeration
//   - GetModuleHandleA / W           - return NULL when asked for our own DLL
//   - GetModuleHandleExA / ExW       - return FALSE/NULL when asked for our own DLL
//   - EnumProcessModules             - filter our HMODULE out of the result list
//   - K32EnumProcessModules          - filter our HMODULE out of the result list
//   - NtQueryVirtualMemory           - hide our memory regions (MemoryBasicInformation)
//                                      and suppress our mapped-file name
//                                      (MemoryMappedFilenameInformation)
//
// Additionally, OptionsUpdated() clears PEB.BeingDebugged so that applications
// which inline the IsDebuggerPresent check also see a clean result.

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <winternl.h>
#include "core/core.h"
#include "hooks/hooks.h"
#include "strings/string_utils.h"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// NtQueryVirtualMemory is not declared in public SDK headers; define it ourselves.
typedef NTSTATUS(NTAPI *PFN_NT_QUERY_VIRTUAL_MEMORY)(HANDLE ProcessHandle, PVOID BaseAddress,
                                                      DWORD MemoryInformationClass,
                                                      PVOID MemoryInformation,
                                                      SIZE_T MemoryInformationLength,
                                                      PSIZE_T ReturnLength);

// Full LDR_DATA_TABLE_ENTRY layout.  The public winternl.h definition obscures
// InLoadOrderLinks and InInitializationOrderLinks behind Reserved fields, so we
// define our own complete version for PEB unlink.
struct RDOC_LDR_DATA_TABLE_ENTRY
{
  LIST_ENTRY InLoadOrderLinks;
  LIST_ENTRY InMemoryOrderLinks;
  LIST_ENTRY InInitializationOrderLinks;
  PVOID DllBase;
  // remaining fields not needed
};

struct RDOC_PEB_LDR_DATA
{
  ULONG Length;
  BOOLEAN Initialized;
  PVOID SsHandle;
  LIST_ENTRY InLoadOrderModuleList;
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
};

typedef BOOL(WINAPI *PFN_IS_DEBUGGER_PRESENT)();
typedef BOOL(WINAPI *PFN_CHECK_REMOTE_DEBUGGER_PRESENT)(HANDLE hProcess,
                                                         PBOOL pbDebuggerPresent);
typedef BOOL(WINAPI *PFN_MODULE32_FIRST_W)(HANDLE hSnapshot, LPMODULEENTRY32W lpme);
typedef BOOL(WINAPI *PFN_MODULE32_NEXT_W)(HANDLE hSnapshot, LPMODULEENTRY32W lpme);
typedef BOOL(WINAPI *PFN_MODULE32_FIRST)(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
typedef BOOL(WINAPI *PFN_MODULE32_NEXT)(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
typedef HMODULE(WINAPI *PFN_GET_MODULE_HANDLE_A)(LPCSTR lpModuleName);
typedef HMODULE(WINAPI *PFN_GET_MODULE_HANDLE_W)(LPCWSTR lpModuleName);
typedef BOOL(WINAPI *PFN_GET_MODULE_HANDLE_EX_A)(DWORD dwFlags, LPCSTR lpModuleName,
                                                  HMODULE *phModule);
typedef BOOL(WINAPI *PFN_GET_MODULE_HANDLE_EX_W)(DWORD dwFlags, LPCWSTR lpModuleName,
                                                  HMODULE *phModule);
typedef BOOL(WINAPI *PFN_ENUM_PROCESS_MODULES)(HANDLE hProcess, HMODULE *lphModule, DWORD cb,
                                               LPDWORD lpcbNeeded);

class StealthHook : LibraryHook
{
public:
  void RegisterHooks()
  {
    RDCLOG("Registering Win32 stealth hooks");

    // capture our own HMODULE and full path so we can recognise ourselves later
    GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCWSTR)&m_OwnModule, &m_OwnModule);

    wchar_t ownPath[MAX_PATH] = {};
    GetModuleFileNameW(m_OwnModule, ownPath, MAX_PATH);
    m_OwnModulePath = strlower(StringFormat::Wide2UTF8(ownPath));

    LibraryHooks::RegisterLibraryHook("kernel32.dll", NULL);
    LibraryHooks::RegisterLibraryHook("psapi.dll", NULL);

    m_IsDebuggerPresent.Register("kernel32.dll", "IsDebuggerPresent", IsDebuggerPresent_hook);
    m_CheckRemoteDebuggerPresent.Register("kernel32.dll", "CheckRemoteDebuggerPresent",
                                          CheckRemoteDebuggerPresent_hook);

    m_Module32FirstW.Register("kernel32.dll", "Module32FirstW", Module32FirstW_hook);
    m_Module32NextW.Register("kernel32.dll", "Module32NextW", Module32NextW_hook);
    m_Module32First.Register("kernel32.dll", "Module32First", Module32First_hook);
    m_Module32Next.Register("kernel32.dll", "Module32Next", Module32Next_hook);

    m_GetModuleHandleA.Register("kernel32.dll", "GetModuleHandleA", GetModuleHandleA_hook);
    m_GetModuleHandleW.Register("kernel32.dll", "GetModuleHandleW", GetModuleHandleW_hook);
    m_GetModuleHandleExA.Register("kernel32.dll", "GetModuleHandleExA", GetModuleHandleExA_hook);
    m_GetModuleHandleExW.Register("kernel32.dll", "GetModuleHandleExW", GetModuleHandleExW_hook);

    m_EnumProcessModules.Register("psapi.dll", "EnumProcessModules", EnumProcessModules_hook);
    m_K32EnumProcessModules.Register("kernel32.dll", "K32EnumProcessModules",
                                     K32EnumProcessModules_hook);

    LibraryHooks::RegisterLibraryHook("ntdll.dll", NULL);
    m_NtQueryVirtualMemory.Register("ntdll.dll", "NtQueryVirtualMemory",
                                    NtQueryVirtualMemory_hook);
  }

  void OptionsUpdated()
  {
    if(!RenderDoc::Inst().GetCaptureOptions().hideFromApplication)
      return;

    // Read PEB base (ABI-stable: GS:[0x60] on x64, FS:[0x30] on x86).
#if defined(_WIN64)
    BYTE *peb = reinterpret_cast<BYTE *>(__readgsqword(0x60));
#else
    BYTE *peb = reinterpret_cast<BYTE *>(__readfsdword(0x30));
#endif
    if(!peb)
      return;

    // Clear PEB.BeingDebugged so that applications which inline IsDebuggerPresent
    // (reading PEB directly via FS/GS segment) also see a clean result.
    // BeingDebugged is at a well-known, ABI-stable offset of 2 bytes from the PEB base.
    peb[2] = 0;

    // Unlink renderdoc.dll from the three PEB loader lists so that code which
    // walks PEB->Ldr directly (without calling any Win32 API) cannot find us.
    UnlinkFromPEB(peb);
  }

private:
  static StealthHook stealth;

  static HMODULE m_OwnModule;
  static rdcstr m_OwnModulePath;    // lowercase UTF-8 full path of renderdoc.dll

  // -----------------------------------------------------------------------
  // PEB LDR unlink
  // -----------------------------------------------------------------------

  // Safely remove a LIST_ENTRY node and point it at itself (idempotent).
  static void RemoveEntryList(LIST_ENTRY *entry)
  {
    entry->Blink->Flink = entry->Flink;
    entry->Flink->Blink = entry->Blink;
    entry->Flink = entry->Blink = entry;    // self-loop so a second removal is a no-op
  }

  // Walk the InLoadOrderModuleList to find our LDR_DATA_TABLE_ENTRY by DllBase,
  // then unlink it from all three loader lists.
  // Safe to call multiple times: after the first call the entry is self-linked
  // and the walk will never find it again.
  static void UnlinkFromPEB(BYTE *peb)
  {
    if(!m_OwnModule)
      return;

    // PEB.Ldr pointer: offset 0x18 (x64) / 0x0C (x86)
#if defined(_WIN64)
    RDOC_PEB_LDR_DATA *ldr = *reinterpret_cast<RDOC_PEB_LDR_DATA **>(peb + 0x18);
#else
    RDOC_PEB_LDR_DATA *ldr = *reinterpret_cast<RDOC_PEB_LDR_DATA **>(peb + 0x0C);
#endif
    if(!ldr)
      return;

    LIST_ENTRY *head = &ldr->InLoadOrderModuleList;
    for(LIST_ENTRY *cur = head->Flink; cur != head; cur = cur->Flink)
    {
      RDOC_LDR_DATA_TABLE_ENTRY *entry =
          CONTAINING_RECORD(cur, RDOC_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

      if(entry->DllBase != (PVOID)m_OwnModule)
        continue;

      // Found our entry - unlink from all three doubly-linked lists.
      RemoveEntryList(&entry->InLoadOrderLinks);
      RemoveEntryList(&entry->InMemoryOrderLinks);
      RemoveEntryList(&entry->InInitializationOrderLinks);

      RDCLOG("Unlinked renderdoc.dll from PEB LDR lists");
      break;
    }
  }

  // -----------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------

  static bool IsStealthEnabled()
  {
    return RenderDoc::Inst().GetCaptureOptions().hideFromApplication;
  }

  // Returns true if hMod is our own DLL.
  static bool IsOwnModule(HMODULE hMod) { return hMod != NULL && hMod == m_OwnModule; }

  // Returns true if the wide path (full or basename) refers to our own DLL.
  static bool IsOwnModuleName(LPCWSTR name)
  {
    if(!name || !name[0])
      return false;
    return IsOwnModuleName(StringFormat::Wide2UTF8(name).c_str());
  }

  // Returns true if the narrow name (full path or basename) refers to our own DLL.
  static bool IsOwnModuleName(LPCSTR name)
  {
    if(!name || !name[0])
      return false;
    rdcstr lower = strlower(rdcstr(name));
    // full-path check
    if(lower == m_OwnModulePath)
      return true;
    // basename check (e.g. "renderdoc.dll")
    return lower == get_basename(m_OwnModulePath);
  }

  // Returns true if the wide ExePath field of a MODULEENTRY corresponds to our DLL.
  static bool IsOwnModulePath(const wchar_t *path)
  {
    if(!path || !path[0])
      return false;
    rdcstr lower = strlower(StringFormat::Wide2UTF8(path));
    return lower == m_OwnModulePath;
  }

  // Returns true if the narrow ExePath field of a MODULEENTRY corresponds to our DLL.
  static bool IsOwnModulePath(const char *path)
  {
    if(!path || !path[0])
      return false;
    rdcstr lower = strlower(rdcstr(path));
    return lower == m_OwnModulePath;
  }

  // Remove our own HMODULE from an EnumProcessModules result buffer.
  static void FilterModuleList(HMODULE *modules, LPDWORD pcbNeeded, DWORD cb)
  {
    DWORD count = *pcbNeeded / sizeof(HMODULE);
    DWORD capacity = cb / sizeof(HMODULE);
    DWORD writeIdx = 0;
    for(DWORD i = 0; i < count && i < capacity; i++)
    {
      if(!IsOwnModule(modules[i]))
        modules[writeIdx++] = modules[i];
    }
    *pcbNeeded = writeIdx * sizeof(HMODULE);
  }

  // -----------------------------------------------------------------------
  // IsDebuggerPresent
  // -----------------------------------------------------------------------

  HookedFunction<PFN_IS_DEBUGGER_PRESENT> m_IsDebuggerPresent;

  static BOOL WINAPI IsDebuggerPresent_hook()
  {
    if(IsStealthEnabled())
      return FALSE;
    return stealth.m_IsDebuggerPresent()();
  }

  // -----------------------------------------------------------------------
  // CheckRemoteDebuggerPresent
  // -----------------------------------------------------------------------

  HookedFunction<PFN_CHECK_REMOTE_DEBUGGER_PRESENT> m_CheckRemoteDebuggerPresent;

  static BOOL WINAPI CheckRemoteDebuggerPresent_hook(HANDLE hProcess, PBOOL pbDebuggerPresent)
  {
    if(IsStealthEnabled() && hProcess == GetCurrentProcess())
    {
      if(pbDebuggerPresent)
        *pbDebuggerPresent = FALSE;
      return TRUE;
    }
    return stealth.m_CheckRemoteDebuggerPresent()(hProcess, pbDebuggerPresent);
  }

  // -----------------------------------------------------------------------
  // Module32FirstW / Module32NextW
  // -----------------------------------------------------------------------

  HookedFunction<PFN_MODULE32_FIRST_W> m_Module32FirstW;
  HookedFunction<PFN_MODULE32_NEXT_W> m_Module32NextW;

  static BOOL WINAPI Module32FirstW_hook(HANDLE hSnapshot, LPMODULEENTRY32W lpme)
  {
    BOOL ret = stealth.m_Module32FirstW()(hSnapshot, lpme);
    if(IsStealthEnabled())
    {
      while(ret && IsOwnModulePath(lpme->szExePath))
        ret = stealth.m_Module32NextW()(hSnapshot, lpme);
    }
    return ret;
  }

  static BOOL WINAPI Module32NextW_hook(HANDLE hSnapshot, LPMODULEENTRY32W lpme)
  {
    BOOL ret = stealth.m_Module32NextW()(hSnapshot, lpme);
    if(IsStealthEnabled())
    {
      while(ret && IsOwnModulePath(lpme->szExePath))
        ret = stealth.m_Module32NextW()(hSnapshot, lpme);
    }
    return ret;
  }

  // -----------------------------------------------------------------------
  // Module32First / Module32Next  (ANSI)
  // -----------------------------------------------------------------------

  HookedFunction<PFN_MODULE32_FIRST> m_Module32First;
  HookedFunction<PFN_MODULE32_NEXT> m_Module32Next;

  static BOOL WINAPI Module32First_hook(HANDLE hSnapshot, LPMODULEENTRY32 lpme)
  {
    BOOL ret = stealth.m_Module32First()(hSnapshot, lpme);
    if(IsStealthEnabled())
    {
      while(ret && IsOwnModulePath(lpme->szExePath))
        ret = stealth.m_Module32Next()(hSnapshot, lpme);
    }
    return ret;
  }

  static BOOL WINAPI Module32Next_hook(HANDLE hSnapshot, LPMODULEENTRY32 lpme)
  {
    BOOL ret = stealth.m_Module32Next()(hSnapshot, lpme);
    if(IsStealthEnabled())
    {
      while(ret && IsOwnModulePath(lpme->szExePath))
        ret = stealth.m_Module32Next()(hSnapshot, lpme);
    }
    return ret;
  }

  // -----------------------------------------------------------------------
  // GetModuleHandleA / GetModuleHandleW
  // -----------------------------------------------------------------------

  HookedFunction<PFN_GET_MODULE_HANDLE_A> m_GetModuleHandleA;
  HookedFunction<PFN_GET_MODULE_HANDLE_W> m_GetModuleHandleW;

  static HMODULE WINAPI GetModuleHandleA_hook(LPCSTR lpModuleName)
  {
    if(IsStealthEnabled() && IsOwnModuleName(lpModuleName))
      return NULL;
    return stealth.m_GetModuleHandleA()(lpModuleName);
  }

  static HMODULE WINAPI GetModuleHandleW_hook(LPCWSTR lpModuleName)
  {
    if(IsStealthEnabled() && IsOwnModuleName(lpModuleName))
      return NULL;
    return stealth.m_GetModuleHandleW()(lpModuleName);
  }

  // -----------------------------------------------------------------------
  // GetModuleHandleExA / GetModuleHandleExW
  // -----------------------------------------------------------------------

  HookedFunction<PFN_GET_MODULE_HANDLE_EX_A> m_GetModuleHandleExA;
  HookedFunction<PFN_GET_MODULE_HANDLE_EX_W> m_GetModuleHandleExW;

  static BOOL WINAPI GetModuleHandleExA_hook(DWORD dwFlags, LPCSTR lpModuleName,
                                             HMODULE *phModule)
  {
    // FROM_ADDRESS means lpModuleName is a pointer, not a string - don't intercept
    if(IsStealthEnabled() && !(dwFlags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS) &&
       IsOwnModuleName(lpModuleName))
    {
      if(phModule)
        *phModule = NULL;
      SetLastError(ERROR_MOD_NOT_FOUND);
      return FALSE;
    }
    return stealth.m_GetModuleHandleExA()(dwFlags, lpModuleName, phModule);
  }

  static BOOL WINAPI GetModuleHandleExW_hook(DWORD dwFlags, LPCWSTR lpModuleName,
                                             HMODULE *phModule)
  {
    if(IsStealthEnabled() && !(dwFlags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS) &&
       IsOwnModuleName(lpModuleName))
    {
      if(phModule)
        *phModule = NULL;
      SetLastError(ERROR_MOD_NOT_FOUND);
      return FALSE;
    }
    return stealth.m_GetModuleHandleExW()(dwFlags, lpModuleName, phModule);
  }

  // -----------------------------------------------------------------------
  // EnumProcessModules / K32EnumProcessModules
  // -----------------------------------------------------------------------

  HookedFunction<PFN_ENUM_PROCESS_MODULES> m_EnumProcessModules;
  HookedFunction<PFN_ENUM_PROCESS_MODULES> m_K32EnumProcessModules;

  static BOOL WINAPI EnumProcessModules_hook(HANDLE hProcess, HMODULE *lphModule, DWORD cb,
                                             LPDWORD lpcbNeeded)
  {
    BOOL ret = stealth.m_EnumProcessModules()(hProcess, lphModule, cb, lpcbNeeded);
    if(ret && IsStealthEnabled() && hProcess == GetCurrentProcess() && lphModule && lpcbNeeded)
      FilterModuleList(lphModule, lpcbNeeded, cb);
    return ret;
  }

  static BOOL WINAPI K32EnumProcessModules_hook(HANDLE hProcess, HMODULE *lphModule, DWORD cb,
                                                LPDWORD lpcbNeeded)
  {
    BOOL ret = stealth.m_K32EnumProcessModules()(hProcess, lphModule, cb, lpcbNeeded);
    if(ret && IsStealthEnabled() && hProcess == GetCurrentProcess() && lphModule && lpcbNeeded)
      FilterModuleList(lphModule, lpcbNeeded, cb);
    return ret;
  }

  // -----------------------------------------------------------------------
  // NtQueryVirtualMemory
  // -----------------------------------------------------------------------
  //
  // MemoryInformationClass values we care about:
  //   0 = MemoryBasicInformation        (MEMORY_BASIC_INFORMATION)
  //   2 = MemoryMappedFilenameInformation (UNICODE_STRING + wchar_t[])
  //
  // For MemoryBasicInformation: if the queried address falls inside our own
  // DLL allocation (AllocationBase == m_OwnModule) we overwrite the result to
  // look like a free region, preventing callers from detecting an injected DLL
  // via address-space scans.
  //
  // For MemoryMappedFilenameInformation: we do a secondary MemoryBasicInformation
  // query to determine the AllocationBase.  If it is ours we return
  // STATUS_INVALID_ADDRESS so the caller sees no backing file.

  HookedFunction<PFN_NT_QUERY_VIRTUAL_MEMORY> m_NtQueryVirtualMemory;

  // Returns true when hProcess refers to the current process.
  static bool IsCurrentProcess(HANDLE hProcess)
  {
    return hProcess == GetCurrentProcess() ||
           hProcess == (HANDLE)(LONG_PTR)-1;    // NtCurrentProcess() pseudo-handle
  }

  static NTSTATUS NTAPI NtQueryVirtualMemory_hook(HANDLE ProcessHandle, PVOID BaseAddress,
                                                   DWORD MemoryInformationClass,
                                                   PVOID MemoryInformation,
                                                   SIZE_T MemoryInformationLength,
                                                   PSIZE_T ReturnLength)
  {
    NTSTATUS ret = stealth.m_NtQueryVirtualMemory()(ProcessHandle, BaseAddress,
                                                    MemoryInformationClass, MemoryInformation,
                                                    MemoryInformationLength, ReturnLength);

    if(!IsStealthEnabled() || !IsCurrentProcess(ProcessHandle) || !NT_SUCCESS(ret))
      return ret;

    // MemoryBasicInformation (class 0)
    if(MemoryInformationClass == 0 && MemoryInformation &&
       MemoryInformationLength >= sizeof(MEMORY_BASIC_INFORMATION))
    {
      MEMORY_BASIC_INFORMATION *mbi = (MEMORY_BASIC_INFORMATION *)MemoryInformation;
      if(mbi->AllocationBase == (PVOID)m_OwnModule)
      {
        // Preserve the address fields so the caller can advance past the region,
        // then zero everything else and mark the region as free.
        PVOID base = mbi->BaseAddress;
        SIZE_T size = mbi->RegionSize;
        RtlZeroMemory(mbi, sizeof(MEMORY_BASIC_INFORMATION));
        mbi->BaseAddress = base;
        mbi->RegionSize = size;
        mbi->State = MEM_FREE;
        // Leave Type / Protect / AllocationBase / AllocationProtect as zero,
        // which is the correct layout for a MEM_FREE region.
      }
    }
    // MemoryMappedFilenameInformation (class 2)
    else if(MemoryInformationClass == 2)
    {
      // Determine the allocation base with a secondary MemoryBasicInformation query.
      MEMORY_BASIC_INFORMATION mbi = {};
      NTSTATUS s = stealth.m_NtQueryVirtualMemory()(ProcessHandle, BaseAddress, 0, &mbi,
                                                    sizeof(mbi), NULL);
      if(NT_SUCCESS(s) && mbi.AllocationBase == (PVOID)m_OwnModule)
        return (NTSTATUS)0xC0000141L;    // STATUS_INVALID_ADDRESS - no file backing visible
    }

    return ret;
  }
};

HMODULE StealthHook::m_OwnModule = NULL;
rdcstr StealthHook::m_OwnModulePath;

StealthHook StealthHook::stealth;
