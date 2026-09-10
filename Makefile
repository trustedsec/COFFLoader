
all: bof bof32 alloc_track alloc_track32
debug: debug32 debug64

bof:
	x86_64-w64-mingw32-gcc -Wall -DCOFF_STANDALONE beacon_compatibility.c COFFLoader.c -o COFFLoader64.exe
	x86_64-w64-mingw32-gcc -c test.c -o test64.out

bof32:
	i686-w64-mingw32-gcc -Wall -DCOFF_STANDALONE beacon_compatibility.c COFFLoader.c -o COFFLoader32.exe
	i686-w64-mingw32-gcc -c test.c -o test32.out

alloc_track:
	x86_64-w64-mingw32-gcc -Wall -DCOFF_STANDALONE -DALLOC_TRACKING beacon_compatibility.c COFFLoader.c alloc_tracker.c -o COFFLoader64_test.exe
	x86_64-w64-mingw32-strip COFFLoader64.exe
	x86_64-w64-mingw32-gcc -c test.c -o test64.out

alloc_track32:
	i686-w64-mingw32-gcc -Wall -DCOFF_STANDALONE -DALLOC_TRACKING beacon_compatibility.c COFFLoader.c alloc_tracker.c -o COFFLoader32_test.exe
	i686-w64-mingw32-strip COFFLoader32.exe
	i686-w64-mingw32-gcc -c test.c -o test32.out

debug64:
	x86_64-w64-mingw32-gcc -DCOFF_STANDALONE -DDEBUG beacon_compatibility.c COFFLoader.c alloc_tracker.c -o COFFLoader64.exe
	x86_64-w64-mingw32-gcc -c test.c -o test64.out

debug32:
	i686-w64-mingw32-gcc -DCOFF_STANDALONE -DDEBUG beacon_compatibility.c COFFLoader.c alloc_tracker.c -o COFFLoader32.exe
	i686-w64-mingw32-gcc -c test.c -o test32.out

nix:
	gcc -DCOFF_STANDALONE -Wall -DDEBUG beacon_compatibility.c COFFLoader.c alloc_tracker.c -o COFFLoader.out

testalloc:
	x86_64-w64-mingw32-gcc -DTEST_ALLOC_TRACKER alloc_tracker.c -o alloc_test.exe

clean:
	rm -f COFFLoader64.exe COFFLoader32.exe COFFLoader.out
	rm -f COFFLoader64_test.exe COFFLoader32_test.exe
	rm -f test32.out test64.out
	rm -f alloc_test.exe

