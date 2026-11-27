/*
 *  MinHook - The Minimalistic API Hooking Library for x64/x86
 *  Copyright (C) 2009-2017 Tsuda Kageyu.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 *  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 *  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
 *  OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <windows.h>
#include "buffer.h"

// Patch 2026: resolved at runtime so the DLL still loads on pre-VirtualAlloc2
// systems. Declared locally rather than relying on SDK macro gating.
typedef struct _MH_ADDRESS_REQUIREMENTS
{
    PVOID LowestStartingAddress;
    PVOID HighestEndingAddress;
    SIZE_T Alignment;
} MH_ADDRESS_REQUIREMENTS;

typedef PVOID(WINAPI* MH_VIRTUALALLOC2)(HANDLE, PVOID, SIZE_T, ULONG, ULONG,
                                        const MH_ADDRESS_REQUIREMENTS*, PVOID, ULONG);

// Size of each memory block. (= page size of VirtualAlloc)
#define MEMORY_BLOCK_SIZE 0x1000

// Memory protection flags to check the executable address.
#define PAGE_EXECUTE_FLAGS \
    (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

// Memory slot.
typedef struct _MEMORY_SLOT
{
    union
    {
        struct _MEMORY_SLOT *pNext;
        UINT8 buffer[MEMORY_SLOT_SIZE];
    };
} MEMORY_SLOT, *PMEMORY_SLOT;

// Memory block info. Placed at the head of each block.
typedef struct _MEMORY_BLOCK
{
    struct _MEMORY_BLOCK *pNext;
    PMEMORY_SLOT pFree;         // First element of the free slot list.
    UINT usedCount;
} MEMORY_BLOCK, *PMEMORY_BLOCK;

//-------------------------------------------------------------------------
// Global Variables:
//-------------------------------------------------------------------------

// First element of the memory block list.
PMEMORY_BLOCK g_pMemoryBlocks;

//-------------------------------------------------------------------------
VOID InitializeBuffer(VOID)
{
    // Nothing to do for now.
}

//-------------------------------------------------------------------------
VOID UninitializeBuffer(VOID)
{
    PMEMORY_BLOCK pBlock = g_pMemoryBlocks;
    g_pMemoryBlocks = NULL;

    while (pBlock)
    {
        PMEMORY_BLOCK pNext = pBlock->pNext;
        VirtualFree(pBlock, 0, MEM_RELEASE);
        pBlock = pNext;
    }
}

//-------------------------------------------------------------------------
// Patch 2026: FindPrevFreeRegion/FindNextFreeRegion and MAX_MEMORY_RANGE were
// removed. Their ±1GB page scan failed on the supported client, where only 4KB
// guard-page gaps exist near a hook target. VirtualAlloc2 now asks the OS for a
// page inside the rel32-safe window; a fallback and the trampoline guard handle
// systems where that is unavailable.

//-------------------------------------------------------------------------
static PMEMORY_BLOCK GetMemoryBlock(LPVOID pOrigin)
{
    PMEMORY_BLOCK pBlock;
    UNREFERENCED_PARAMETER(pOrigin);

    // Look the registered blocks for one with a free slot. Blocks are now
    // requested inside a rel32-safe window around their first target; the
    // guard in CreateTrampolineFunction still rejects any that end up too far
    // from a later target.
    for (pBlock = g_pMemoryBlocks; pBlock != NULL; pBlock = pBlock->pNext)
    {
        // The block has at least one unused slot.
        if (pBlock->pFree != NULL)
            return pBlock;
    }

    // Patch 2026: ask the OS for a block inside the signed-32-bit range of the
    // target. RIP-relative operands copied into the trampoline are rewritten
    // as 32-bit displacements, so a distant block can make them unusable.
    // VirtualAlloc2 is resolved dynamically because it is Windows 10+ only.
    {
        HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        MH_VIRTUALALLOC2 virtualAlloc2 = kernel32 != NULL
            ? (MH_VIRTUALALLOC2)GetProcAddress(kernel32, "VirtualAlloc2")
            : NULL;
        if (virtualAlloc2 != NULL)
        {
            SYSTEM_INFO si;
            ULONG_PTR low, high, origin = (ULONG_PTR)pOrigin;
            GetSystemInfo(&si);
            low = (ULONG_PTR)si.lpMinimumApplicationAddress;
            high = (ULONG_PTR)si.lpMaximumApplicationAddress;
            if (origin > (ULONG_PTR)0x7FFFFFFF && low < origin - (ULONG_PTR)0x7FFFFFFF)
                low = origin - (ULONG_PTR)0x7FFFFFFF;
            if (high > origin + (ULONG_PTR)0x7FFFFFFF)
                high = origin + (ULONG_PTR)0x7FFFFFFF;
            if (low < high)
            {
                MH_ADDRESS_REQUIREMENTS requirements = {
                    (PVOID)low, (PVOID)high, si.dwAllocationGranularity};
                pBlock = (PMEMORY_BLOCK)virtualAlloc2(GetCurrentProcess(), NULL, MEMORY_BLOCK_SIZE,
                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE, &requirements, NULL, 0);
            }
        }
    }

    // Fallback for systems without VirtualAlloc2, or when no page exists in
    // the window. The RIP-relative guard turns an unusable block into a safe
    // hook-creation failure instead of a wrong jump.
    if (pBlock == NULL)
        pBlock = (PMEMORY_BLOCK)VirtualAlloc(
            NULL, MEMORY_BLOCK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (pBlock != NULL)
    {
        // Build a linked list of all the slots.
        PMEMORY_SLOT pSlot = (PMEMORY_SLOT)pBlock + 1;
        pBlock->pFree = NULL;
        pBlock->usedCount = 0;
        do
        {
            pSlot->pNext = pBlock->pFree;
            pBlock->pFree = pSlot;
            pSlot++;
        } while ((ULONG_PTR)pSlot - (ULONG_PTR)pBlock <= MEMORY_BLOCK_SIZE - MEMORY_SLOT_SIZE);

        pBlock->pNext = g_pMemoryBlocks;
        g_pMemoryBlocks = pBlock;
    }

    return pBlock;
}

//-------------------------------------------------------------------------
LPVOID AllocateBuffer(LPVOID pOrigin)
{
    PMEMORY_SLOT  pSlot;
    PMEMORY_BLOCK pBlock = GetMemoryBlock(pOrigin);
    if (pBlock == NULL)
        return NULL;

    // Remove an unused slot from the list.
    pSlot = pBlock->pFree;
    pBlock->pFree = pSlot->pNext;
    pBlock->usedCount++;
#ifdef _DEBUG
    // Fill the slot with INT3 for debugging.
    memset(pSlot, 0xCC, sizeof(MEMORY_SLOT));
#endif
    return pSlot;
}

//-------------------------------------------------------------------------
VOID FreeBuffer(LPVOID pBuffer)
{
    PMEMORY_BLOCK pBlock = g_pMemoryBlocks;
    PMEMORY_BLOCK pPrev = NULL;
    ULONG_PTR pTargetBlock = ((ULONG_PTR)pBuffer / MEMORY_BLOCK_SIZE) * MEMORY_BLOCK_SIZE;

    while (pBlock != NULL)
    {
        if ((ULONG_PTR)pBlock == pTargetBlock)
        {
            PMEMORY_SLOT pSlot = (PMEMORY_SLOT)pBuffer;
#ifdef _DEBUG
            // Clear the released slot for debugging.
            memset(pSlot, 0x00, sizeof(*pSlot));
#endif
            // Restore the released slot to the list.
            pSlot->pNext = pBlock->pFree;
            pBlock->pFree = pSlot;
            pBlock->usedCount--;

            // Free if unused.
            if (pBlock->usedCount == 0)
            {
                if (pPrev)
                    pPrev->pNext = pBlock->pNext;
                else
                    g_pMemoryBlocks = pBlock->pNext;

                VirtualFree(pBlock, 0, MEM_RELEASE);
            }

            break;
        }

        pPrev = pBlock;
        pBlock = pBlock->pNext;
    }
}

//-------------------------------------------------------------------------
BOOL IsExecutableAddress(LPVOID pAddress)
{
    MEMORY_BASIC_INFORMATION mi;
    VirtualQuery(pAddress, &mi, sizeof(mi));

    return (mi.State == MEM_COMMIT && (mi.Protect & PAGE_EXECUTE_FLAGS));
}
