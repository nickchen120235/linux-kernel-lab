# README

## How to use
1. `make` to compile the kernel module
2. `make insert` to insert it
3. `make test` to compile `test.c`
4. run `./test` inside tmux or any other way to create the process
5. `make listvma` to initiate the `listvma` command
6. `make findpage addr=<addr>` to `findpage` at `<addr>`
7. `make writeval addr=<addr> val=<val>` to `writeval` `<val>` at `<addr>`