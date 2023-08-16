# Zermatt

Download the Lua module `bit32`, then add the following line to the packed
Lua file to run it:

```lua
require "bit32";
```

Launch the Lua VM in gdb

```sh
$ gdb --args lu5.3 zermatt.lua 

```

Set a breakpoint on `exit()` and dump the heap:

```
gef➤ info proc mappings
...
0x555555598000     0x5555555da000    0x42000        0x0  rw-p   [heap]
...

gef➤ pipe x/270336s 0x555555598000 | grep CTF
0x5555555ce6d8: "CTF{At_least_it_was_not_a_bytecode_base_sandbox_escape}"
```


