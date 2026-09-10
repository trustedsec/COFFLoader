#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "alloc_tracker.h"

AllocEntry* g_alloc_list = NULL;
int g_failure_count = 0;

#define GUARD_PAGE_SIZE (4096)

#ifdef DEBUG
#define DEBUG_PRINT(x, ...) printf(x, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(x, ...)
#endif

void init_alloc_tracker(void) {
    DEBUG_PRINT("DEBUG: init_alloc_tracker called\n"); fflush(stdout);
    g_alloc_list = NULL;
    g_failure_count = 0;
}

static AllocEntry* find_entry(void* ptr) {
    AllocEntry* current = g_alloc_list;
    while (current != NULL) {
        if (current->ptr == ptr) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

void track_allocation(void* ptr, size_t requested_size, size_t total_allocated, AllocType type) {
    DEBUG_PRINT("DEBUG: track_allocation called with ptr=%p\n", ptr); fflush(stdout);
    AllocEntry* entry = HeapAlloc(GetProcessHeap(), 0, sizeof(AllocEntry));
    DEBUG_PRINT("DEBUG: HeapAlloc returned %p\n", entry); fflush(stdout);
    
    if (entry != NULL) {
        entry->ptr = ptr;
        entry->requested_size = requested_size;
        entry->total_allocated = total_allocated;
        entry->timestamp = GetTickCount();
        entry->type = type;
        entry->next = g_alloc_list;
        g_alloc_list = entry;
        DEBUG_PRINT("DEBUG: track_allocation done, list now has %p at head\n", g_alloc_list); fflush(stdout);
        DEBUG_PRINT("DEBUG: g_alloc_list = %p\n", g_alloc_list); fflush(stdout);
        DEBUG_PRINT("DEBUG: g_alloc_list->next = %p\n", g_alloc_list ? g_alloc_list->next : NULL); fflush(stdout);
    }
    else{
        DEBUG_PRINT("DEBUG: Entry isn't allocated\n");
    }
}

void track_free(void* ptr) {
    AllocEntry** pp = &g_alloc_list;
    while (*pp != NULL) {
        if ((*pp)->ptr == ptr) {
            AllocEntry* entry = *pp;
            DEBUG_PRINT("DEBUG: Found entry to free at %p, removing from list\n", entry); fflush(stdout);
            *pp = entry->next;
            HeapFree(GetProcessHeap(), 0, entry);
            return;
        }
        pp = &(*pp)->next;
    }
    
    DEBUG_PRINT("ERROR: Freeing untracked pointer %p\n", ptr);
    abort();
}

BOOL validate_guard_pages(void* ptr) {
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T result = VirtualQuery(ptr, &mbi, sizeof(mbi));
    
    if (result == 0) {
        return FALSE;
    }
    
    if (mbi.State == MEM_COMMIT && mbi.Protect == PAGE_NOACCESS) {
        return TRUE;
    }
    
    DWORD oldProtect;
    if (VirtualQuery(ptr, &mbi, sizeof(mbi)) > 0) {
        if (VirtualProtect(ptr, GUARD_PAGE_SIZE, PAGE_READWRITE, &oldProtect)) {
            BYTE* checkBytes = (BYTE*)ptr;
            for (int i = 0; i < GUARD_PAGE_SIZE; i++) {
                if (checkBytes[i] != 0) {
                    VirtualProtect(ptr, GUARD_PAGE_SIZE, oldProtect, &oldProtect);
                    return FALSE;
                }
            }
            VirtualProtect(ptr, GUARD_PAGE_SIZE, oldProtect, &oldProtect);
        }
    }
    
    return TRUE;
}

char* get_leak_summary(int* leak_count, size_t* total_leaked) {
    int count = 0;
    size_t total = 0;
    AllocEntry* current = g_alloc_list;
    
    while (current != NULL) {
        count++;
        total += current->requested_size;
        current = current->next;
    }
    
    *leak_count = count;
    *total_leaked = total;
    
    char* buffer = HeapAlloc(GetProcessHeap(), 0, 4096);
    if (buffer == NULL) {
        return NULL;
    }
    
    int offset = 0;
    offset += sprintf(buffer + offset, "Memory Leak Summary\n");
    offset += sprintf(buffer + offset, "===================\n");
    offset += sprintf(buffer + offset, "Total Leaked Allocations: %d\n", count);
    offset += sprintf(buffer + offset, "Total Bytes Leaked: %zu\n\n", total);
    
    if (count > 0) {
        offset += sprintf(buffer + offset, "Address           Size    Type         Timestamp\n");
        offset += sprintf(buffer + offset, "----------------- ------- ------------ ------------------\n");
        
        current = g_alloc_list;
        while (current != NULL) {
            const char* typeStr = "UNKNOWN";
            switch (current->type) {
                case ALLOC_TYPE_MALLOC: typeStr = "MALLOC"; break;
                case ALLOC_TYPE_CALLOC: typeStr = "CALLOC"; break;
                case ALLOC_TYPE_REALLOC: typeStr = "REALLOC"; break;
                case ALLOC_TYPE_HEAP_ALLOC: typeStr = "HEAP_ALLOC"; break;
                case ALLOC_TYPE_HEAP_REALLOC: typeStr = "HEAP_REALLOC"; break;
            }
            
            offset += sprintf(buffer + offset, "%-16p  %-7zu %-12s %lu\n", 
                             current->ptr, current->requested_size, typeStr, 
                             (unsigned long)current->timestamp);
            
            BYTE* userPtrEnd = (BYTE*)current->ptr + current->requested_size;
            BYTE* paddedEnd = (BYTE*)((DWORD_PTR)(userPtrEnd + GUARD_PAGE_SIZE - 1) & ~(GUARD_PAGE_SIZE - 1));
            for (int i = 0; i < paddedEnd - userPtrEnd; i++) {
                if (userPtrEnd[i] != 0xFF) {
                    g_failure_count++;
                }
            }
            
            current = current->next;
        }
    } else {
        offset += sprintf(buffer + offset, "No memory leaks detected.\n");
    }
    
    offset += sprintf(buffer + offset, "\nMemory Corruption Summary\n");
    offset += sprintf(buffer + offset, "=========================\n");
    offset += sprintf(buffer + offset, "Total Validation Failures: %d\n", g_failure_count);
    
    return buffer;
}

void cleanup_alloc_tracker(void) {
    AllocEntry* current = g_alloc_list;
    while (current != NULL) {
        AllocEntry* next = current->next;
        HeapFree(GetProcessHeap(), 0, current);
        current = next;
    }
    g_alloc_list = NULL;
    g_failure_count = 0;
}

void* tracked_malloc(size_t size) {
    size_t total_size = (size + GUARD_PAGE_SIZE * 2 + GUARD_PAGE_SIZE - 1) & ~(GUARD_PAGE_SIZE - 1);
    DEBUG_PRINT("DEBUG: About to call HeapAlloc for %zu rounded up to %zu bytes\n", size, total_size); fflush(stdout);
    DEBUG_PRINT("DEBUG: Before HeapAlloc\n"); fflush(stdout);
    void* ptr = VirtualAlloc(NULL, total_size, MEM_COMMIT|MEM_RESERVE|MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);
    DEBUG_PRINT("DEBUG: VirtualAlloc returned %p\n", ptr); fflush(stdout);
    
    if (ptr == NULL) {
        return NULL;
    }
    
    BYTE* guardStart = (BYTE*)ptr;
    BYTE* userPtr = guardStart + GUARD_PAGE_SIZE;
    BYTE* endGuard = userPtr + size;
    endGuard = (BYTE*)((DWORD_PTR)(endGuard + GUARD_PAGE_SIZE - 1) & ~(GUARD_PAGE_SIZE - 1));
    
    DWORD oldProtect;
    BOOL r1 = VirtualProtect(guardStart, GUARD_PAGE_SIZE, PAGE_READWRITE, &oldProtect);
    DEBUG_PRINT("DEBUG: VirtualProtect 1 returned %d\n", r1); fflush(stdout);
    (void)r1;
    
    memset(guardStart, 0, GUARD_PAGE_SIZE);
    DEBUG_PRINT("DEBUG: memset guardStart done\n"); fflush(stdout);
    
    BOOL r2 = VirtualProtect(guardStart, GUARD_PAGE_SIZE, PAGE_NOACCESS, &oldProtect);
    DEBUG_PRINT("DEBUG: VirtualProtect 2 returned %d\n", r2); fflush(stdout);
    (void)r2;
    
    BOOL r3 = VirtualProtect(endGuard, GUARD_PAGE_SIZE, PAGE_READWRITE, &oldProtect);
    DEBUG_PRINT("DEBUG: VirtualProtect 3 returned %d\n", r3); fflush(stdout);
    (void)r3;
    
    memset(endGuard, 0, GUARD_PAGE_SIZE);
    DEBUG_PRINT("DEBUG: memset endGuard done\n"); fflush(stdout);
    
    BOOL r4 = VirtualProtect(endGuard, GUARD_PAGE_SIZE, PAGE_NOACCESS, &oldProtect);
    DEBUG_PRINT("DEBUG: VirtualProtect 4 returned %d\n", r4); fflush(stdout);
    (void)r4;
    
    BYTE* userPtrEnd = userPtr + size;
    BYTE* paddedEnd = (BYTE*)((DWORD_PTR)(userPtrEnd + GUARD_PAGE_SIZE - 1) & ~(GUARD_PAGE_SIZE - 1));
    memset(userPtrEnd, 0xFF, paddedEnd - userPtrEnd);
    
    track_allocation(userPtr, size, total_size, ALLOC_TYPE_MALLOC);
    
    return userPtr;
}

void* tracked_calloc(size_t nmemb, size_t size) {
    size_t total = nmemb * size;
    void* ptr = tracked_malloc(total);
    if (ptr == NULL) {
        return NULL;
    }
    memset(ptr, 0, total);
    return ptr;
}

void* tracked_realloc(void* ptr, size_t size) {
    DEBUG_PRINT("DEBUG: tracked_realloc called with ptr=%p, size=%zu\n", ptr, size); fflush(stdout);
    
    if (ptr == NULL) {
        return tracked_malloc(size);
    }
    
    AllocEntry* entry = find_entry(ptr);
    if (entry == NULL) {
        DEBUG_PRINT("ERROR: Realloc of untracked pointer %p\n", ptr);
        abort();
    }
    
    void* newPtr = tracked_malloc(size);
    if (newPtr == NULL) {
        return NULL;
    }
    
    size_t copySize = entry->requested_size < size ? entry->requested_size : size;
    DEBUG_PRINT("DEBUG: memcpy %zu bytes from %p to %p\n", copySize, ptr, newPtr); fflush(stdout);
    memcpy(newPtr, ptr, copySize);
    DEBUG_PRINT("DEBUG: memcpy done\n"); fflush(stdout);
    
    track_free(ptr);
    
    return newPtr;
}

void tracked_free(void* ptr) {
    if (ptr == NULL) {
        return;
    }
    
    AllocEntry* entry = find_entry(ptr);
    if (entry == NULL) {
        DEBUG_PRINT("ERROR: Freeing untracked pointer %p\n", ptr);
        abort();
    }
    
    track_free(ptr);
    
    BYTE* userPtr = (BYTE*)ptr;
    BYTE* guardStart = userPtr - GUARD_PAGE_SIZE;
    size_t allocSize = entry->total_allocated;
    
    DEBUG_PRINT("DEBUG: About to validate guard pages at %p\n", guardStart); fflush(stdout);
    
    BYTE* userPtrEnd = userPtr + entry->requested_size;
    BYTE* paddedEnd = (BYTE*)((DWORD_PTR)(userPtrEnd + GUARD_PAGE_SIZE - 1) & ~(GUARD_PAGE_SIZE - 1));
    for (int i = 0; i < paddedEnd - userPtrEnd; i++) {
        if (userPtrEnd[i] != 0xFF) {
            DEBUG_PRINT("FATAL: Memory corruption detected at %p, byte %d of padding modified (expected 0xFF, got 0x%02X)\n", 
                       ptr, i, userPtrEnd[i]);
            g_failure_count++;
        }
    }
    
    DWORD oldProtect;
    VirtualProtect(guardStart, allocSize - GUARD_PAGE_SIZE, PAGE_READWRITE, &oldProtect);
    memset(guardStart, 0xFF, allocSize - GUARD_PAGE_SIZE);
    VirtualProtect(guardStart, allocSize - GUARD_PAGE_SIZE, oldProtect, &oldProtect);
    
    VirtualFree(guardStart, 0, MEM_RELEASE);
}

void* tracked_heap_alloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes) {
    size_t total_size = (dwBytes + GUARD_PAGE_SIZE * 2 + GUARD_PAGE_SIZE - 1) & ~(GUARD_PAGE_SIZE - 1);
    void* ptr = VirtualAlloc(NULL, total_size, MEM_COMMIT|MEM_RESERVE|MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);
    if (ptr == NULL) {
        return NULL;
    }
    
    BYTE* guardStart = (BYTE*)ptr;
    BYTE* userPtr = guardStart + GUARD_PAGE_SIZE;
    BYTE* endGuard = userPtr + dwBytes;
    endGuard = (BYTE*)((DWORD_PTR)(endGuard + GUARD_PAGE_SIZE - 1) & ~(GUARD_PAGE_SIZE - 1));
    
    DWORD oldProtect;
    VirtualProtect(guardStart, GUARD_PAGE_SIZE, PAGE_READWRITE, &oldProtect);
    memset(guardStart, 0, GUARD_PAGE_SIZE);
    VirtualProtect(guardStart, GUARD_PAGE_SIZE, PAGE_NOACCESS, &oldProtect);
    
    VirtualProtect(endGuard, GUARD_PAGE_SIZE, PAGE_READWRITE, &oldProtect);
    memset(endGuard, 0, GUARD_PAGE_SIZE);
    VirtualProtect(endGuard, GUARD_PAGE_SIZE, PAGE_NOACCESS, &oldProtect);
    
    BYTE* userPtrEnd = userPtr + dwBytes;
    BYTE* paddedEnd = (BYTE*)((DWORD_PTR)(userPtrEnd + GUARD_PAGE_SIZE - 1) & ~(GUARD_PAGE_SIZE - 1));
    memset(userPtrEnd, 0xFF, paddedEnd - userPtrEnd);
    
    track_allocation(userPtr, dwBytes, total_size, ALLOC_TYPE_HEAP_ALLOC);
    
    return userPtr;
}

BOOL tracked_heap_free(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem) {
    if (lpMem == NULL) {
        return TRUE;
    }
    
    AllocEntry* entry = find_entry(lpMem);
    if (entry == NULL) {
        DEBUG_PRINT("ERROR: HeapFree of untracked pointer %p\n", lpMem);
        abort();
    }
    
    track_free(lpMem);
    
    BYTE* userPtr = (BYTE*)lpMem;
    BYTE* guardStart = userPtr - GUARD_PAGE_SIZE;
    
    DWORD oldProtect;
    VirtualProtect(guardStart, entry->total_allocated - GUARD_PAGE_SIZE, PAGE_READWRITE, &oldProtect);
    
    BYTE* userPtrEnd = userPtr + entry->requested_size;
    BYTE* paddedEnd = (BYTE*)((DWORD_PTR)(userPtrEnd + GUARD_PAGE_SIZE - 1) & ~(GUARD_PAGE_SIZE - 1));
    for (int i = 0; i < paddedEnd - userPtrEnd; i++) {
        if (userPtrEnd[i] != 0xFF) {
            DEBUG_PRINT("FATAL: Memory corruption detected at %p, byte %d of padding modified (expected 0xFF, got 0x%02X)\n", 
                       lpMem, i, userPtrEnd[i]);
            g_failure_count++;
        }
    }
    
    memset(guardStart, 0xFF, entry->total_allocated - GUARD_PAGE_SIZE);
    VirtualProtect(guardStart, entry->total_allocated - GUARD_PAGE_SIZE, oldProtect, &oldProtect);
    
    return VirtualFree(guardStart, 0, MEM_RELEASE);
}

void* tracked_heap_realloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes) {
    if (lpMem == NULL) {
        return tracked_heap_alloc(hHeap, dwFlags, dwBytes);
    }
    
    AllocEntry* entry = find_entry(lpMem);
    if (entry == NULL) {
        DEBUG_PRINT("ERROR: HeapRealloc of untracked pointer %p\n", lpMem);
        abort();
    }
    
    track_free(lpMem);
    
    void* newPtr = tracked_heap_alloc(hHeap, dwFlags, dwBytes);
    if (newPtr == NULL) {
        return NULL;
    }
    
    size_t copySize = entry->requested_size < dwBytes ? entry->requested_size : dwBytes;
    memcpy(newPtr, lpMem, copySize);
    
    track_free(lpMem);
    
    return newPtr;
}

#ifdef TEST_ALLOC_TRACKER

int test_linked_list_operations(void) {
    DEBUG_PRINT("DEBUG: Starting test_linked_list_operations\n"); fflush(stdout);
    int errors = 0;
    
    DEBUG_PRINT("DEBUG: test_linked_list_operations - clearing list\n"); fflush(stdout);
    g_alloc_list = NULL;
    
    DEBUG_PRINT("DEBUG: test_linked_list_operations - calling tracked_malloc for p1 (100)\n"); fflush(stdout);
    void* p1 = tracked_malloc(100);
    if (p1 == NULL) {
        DEBUG_PRINT("FAIL: First allocation failed\n");
        return 1;
    }
    
    DEBUG_PRINT("DEBUG: test_linked_list_operations - checking p1 size\n"); fflush(stdout);
    if (g_alloc_list->requested_size != 100) {
        DEBUG_PRINT("FAIL: Size not correct after first alloc\n");
        errors++;
    } else {
        DEBUG_PRINT("PASS: First entry inserted with correct size\n");
    }
    
    DEBUG_PRINT("DEBUG: test_linked_list_operations - calling tracked_malloc for p2 (200)\n"); fflush(stdout);
    void* p2 = tracked_malloc(200);
    if (p2 == NULL) {
        DEBUG_PRINT("FAIL: Second allocation failed\n");
        return 1;
    }
    
    DEBUG_PRINT("DEBUG: test_linked_list_operations - checking list structure after p2\n"); fflush(stdout);
    if (g_alloc_list->requested_size != 200 || g_alloc_list->next == NULL || g_alloc_list->next->requested_size != 100) {
        DEBUG_PRINT("FAIL: Linked list not correct after second alloc\n");
        errors++;
    } else {
        DEBUG_PRINT("PASS: Second entry inserted at head with first linked after\n");
    }
    
    DEBUG_PRINT("DEBUG: test_linked_list_operations - calling tracked_malloc for p3 (300)\n"); fflush(stdout);
    void* p3 = tracked_malloc(300);
    if (p3 == NULL) {
        DEBUG_PRINT("FAIL: Third allocation failed\n");
        return 1;
    }
    
    if (g_alloc_list->requested_size != 300 || g_alloc_list->next == NULL || g_alloc_list->next->requested_size != 200) {
        DEBUG_PRINT("FAIL: Linked list not correct after third alloc\n");
        errors++;
    } else {
        DEBUG_PRINT("PASS: Third entry inserted at head with rest linked correctly\n");
    }
    
    AllocEntry* found = find_entry(p2);
    if (found == NULL || found->ptr != p2) {
        DEBUG_PRINT("FAIL: Could not find p2 in list\n");
        errors++;
    } else {
        DEBUG_PRINT("PASS: Found p2 in list\n");
    }
    
    AllocEntry* not_found = find_entry((void*)0x9999);
    if (not_found != NULL) {
        DEBUG_PRINT("FAIL: Found non-existent entry\n");
        errors++;
    } else {
        DEBUG_PRINT("PASS: Non-existent entry not found\n");
    }
    
    tracked_free(p2);
    if (find_entry(p2) != NULL) {
        DEBUG_PRINT("FAIL: p2 still in list after free\n");
        errors++;
    } else {
        DEBUG_PRINT("PASS: p2 removed from list\n");
    }
    
    tracked_free(p1);
    tracked_free(p3);
    
    if (g_alloc_list != NULL) {
        DEBUG_PRINT("FAIL: List not empty after all frees\n");
        errors++;
    } else {
        DEBUG_PRINT("PASS: List empty after all frees\n");
    }
    
    cleanup_alloc_tracker();
    
    return errors;
}

int test_multiple_allocations(void) {
    int errors = 0;
    
    DEBUG_PRINT("\nDEBUG: Starting test_multiple_allocations\n"); fflush(stdout);
    
    g_alloc_list = NULL;
    
    void* ptrs[10];
    size_t sizes[10] = {50, 100, 150, 200, 250, 300, 350, 400, 450, 500};
    
    for (int i = 0; i < 10; i++) {
        DEBUG_PRINT("DEBUG: test_multiple_allocations - calling tracked_malloc[%d] (%zu)\n", i, sizes[i]); fflush(stdout);
        ptrs[i] = tracked_malloc(sizes[i]);
        if (ptrs[i] == NULL) {
            DEBUG_PRINT("FAIL: Could not allocate memory %d\n", i);
            errors++;
            continue;
        }
    }
    
    int count = 0;
    AllocEntry* current = g_alloc_list;
    while (current != NULL) {
        count++;
        current = current->next;
    }
    
    if (count == 10) {
        DEBUG_PRINT("PASS: All 10 allocations tracked\n");
    } else {
        DEBUG_PRINT("FAIL: Expected 10 entries, got %d\n", count);
        errors++;
    }
    
    size_t total_size = 0;
    current = g_alloc_list;
    while (current != NULL) {
        total_size += current->requested_size;
        current = current->next;
    }
    
    size_t expected_total = 50 + 100 + 150 + 200 + 250 + 300 + 350 + 400 + 450 + 500;
    if (total_size == expected_total) {
        DEBUG_PRINT("PASS: Total size correct: %zu\n", total_size);
    } else {
        DEBUG_PRINT("FAIL: Expected total size %zu, got %zu\n", expected_total, total_size);
        errors++;
    }
    
    for (int i = 0; i < 10; i++) {
        tracked_free(ptrs[i]);
    }
    
    if (g_alloc_list == NULL) {
        DEBUG_PRINT("PASS: All entries freed and list empty\n");
    } else {
        DEBUG_PRINT("FAIL: List not empty after freeing all\n");
        errors++;
    }
    
    cleanup_alloc_tracker();
    
    return errors;
}

int test_realloc_operations(void) {
    int errors = 0;
    
    DEBUG_PRINT("\nDEBUG: Starting test_realloc_operations\n"); fflush(stdout);
    
    g_alloc_list = NULL;
    
    void* p1 = tracked_malloc(100);
    if (g_alloc_list->requested_size != 100) {
        DEBUG_PRINT("FAIL: Initial size not correct\n");
        errors++;
    } else {
        DEBUG_PRINT("PASS: Initial size is 100\n");
    }
    
    void* p2 = tracked_realloc(p1, 200);
    if (p2 == NULL) {
        DEBUG_PRINT("FAIL: Realloc failed\n");
        errors++;
    } else if (g_alloc_list->requested_size != 200) {
        DEBUG_PRINT("FAIL: Size not updated to 200\n");
        errors++;
    } else {
        DEBUG_PRINT("PASS: Size updated to 200 after realloc\n");
    }
    
    tracked_free(p2);
    cleanup_alloc_tracker();
    
    return errors;
}

int test_null_handling(void) {
    int errors = 0;
    
    DEBUG_PRINT("\nDEBUG: Starting test_null_handling\n"); fflush(stdout);
    
    g_alloc_list = NULL;
    
    void* p = tracked_malloc(50);
    if (p == NULL) {
        DEBUG_PRINT("FAIL: tracked_malloc returned NULL\n");
        errors++;
    } else {
        DEBUG_PRINT("PASS: tracked_malloc returned valid pointer\n");
    }
    
    tracked_free(p);
    
    tracked_free(NULL);
    
    if (g_alloc_list != NULL) {
        DEBUG_PRINT("FAIL: List not empty after free\n");
        errors++;
    } else {
        DEBUG_PRINT("PASS: List empty after freeing and freeing NULL\n");
    }
    
    cleanup_alloc_tracker();
    
    return errors;
}

int main(void) {
    DEBUG_PRINT("=== alloc_tracker.c Test Suite ===\n\n");
    fflush(stdout);
    
    int total_errors = 0;
    
    total_errors += test_linked_list_operations();
    if (total_errors > 0) {
        DEBUG_PRINT("\nTest failed, stopping.\n");
        return 1;
    }
    
    total_errors += test_multiple_allocations();
    if (total_errors > 0) {
        DEBUG_PRINT("\nTest failed, stopping.\n");
        return 1;
    }
    
    total_errors += test_realloc_operations();
    if (total_errors > 0) {
        DEBUG_PRINT("\nTest failed, stopping.\n");
        return 1;
    }
    
    total_errors += test_null_handling();
    
    DEBUG_PRINT("\n=== Test Results ===\n");
    if (total_errors == 0) {
        DEBUG_PRINT("All tests passed!\n");
        return 0;
    } else {
        DEBUG_PRINT("%d test(s) failed\n", total_errors);
        return 1;
    }
}
#endif
