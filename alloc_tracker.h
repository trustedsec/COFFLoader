#ifndef ALLOC_TRACKER_H_
#define ALLOC_TRACKER_H_

#include <windows.h>
#include <stddef.h>

typedef enum {
    ALLOC_TYPE_MALLOC,
    ALLOC_TYPE_CALLOC,
    ALLOC_TYPE_REALLOC,
    ALLOC_TYPE_HEAP_ALLOC,
    ALLOC_TYPE_HEAP_REALLOC
} AllocType;

typedef struct AllocEntry {
    void* ptr;
    size_t requested_size;
    size_t total_allocated;
    time_t timestamp;
    AllocType type;
    struct AllocEntry* next;
} AllocEntry;

void init_alloc_tracker(void);
void track_allocation(void* ptr, size_t requested_size, size_t total_allocated, AllocType type);
void track_free(void* ptr);
BOOL validate_guard_pages(void* ptr);
char* get_leak_summary(int* leak_count, size_t* total_leaked);
void cleanup_alloc_tracker(void);

void* tracked_malloc(size_t size);
void* tracked_calloc(size_t nmemb, size_t size);
void* tracked_realloc(void* ptr, size_t size);
void tracked_free(void* ptr);
void* tracked_heap_alloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
BOOL tracked_heap_free(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
void* tracked_heap_realloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes);

extern AllocEntry* g_alloc_list;
extern int g_failure_count;
#ifdef TEST_ALLOC_TRACKER
extern CRITICAL_SECTION g_alloc_lock;
#endif

#endif
