# COFF Loader

This is a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it. The only exception is that the injection related beacon compatibility functions are just empty.

The main goal is to provide a working example and maybe be useful to someone.


## Parts
There are a few parts to it they are listed below.

- beacon_compatibility: This is the beacon internal functions so that you can load BOF files and run them.
- COFFLoader: This is the actual coff loader, and when built for nix just loads the 64 bit object file and parses it.
- test: This is the example "COFF" file, will build to the COFF file for you when make is called.

