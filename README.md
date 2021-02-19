# COFF Loader

This is a quick and dirty COFF loader (AKA Beacon Object Files), will eventually get it able to run a default BOF without changes, so that it can be used for testing without a CS agent running it.

The main goal is to provide a working example and maybe be useful to someone.


## Parts
There are a few parts to it they are listed below.

- beacon_compatibility: This will be the beacon internal functions so that you can load BOF files and run them inside your own agent, currently not used.
- COFFLoader: This is the actual coff loader, and when built for nix just loads the 64 bit object file and parses it.
- test: This is the example "COFF" file, will build to the COFF file for you when make is called.

