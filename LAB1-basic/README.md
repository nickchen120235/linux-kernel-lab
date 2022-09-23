# Linux Kernel Module Programming 1

## Regarding Makefile
All Makefiles share the same set of commands
- `make` to compile the modules
- `make clean` to clear generated files
- `make insert` to insert the module
  - for mod_2, parameters can be added directly after the command, for example `make insert my_int=12345 my_int_array=1,2,3,4,5 my_string="TEST"`
- `make remove` to remove the module