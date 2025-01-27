binpattern
==========
Extract binary patterns, useful for yaras.

It scan only .text section (if the code is in other section, it's not supported now)

Why only code?
string patters can be done manually in a better way, understanding what is every string.
Normally yaras has a lack of code patterns, that are more hidden to the human eye.

Author
------
sha0coder

with interesting ideas of Peter to implement.


Usage
-----
arg1: folder to start the recusrive lookup of .bin .exe and .dll
arg2: pattern length ideally 10-25 or sometimes less.
arg3: hello world compiled with same compiler to exclude runtime patterns.

cargo run --release --  ~/samples/ 10 runtime/golang_hello_world.exe

...
  Compiler: Golang
  Architecture: x86 (32-bit)
  GUI: Yes

loaded 6 .text blobs
$code01 = {648b098b093b6108762583ec0c8b442410840089}
$code02 = {008904248b442424894424088b44242089442404}
$code03 = {8b093b6108762583ec0c8b4424108400890424e8}
$code04 = {093b6108762583ec0c8b44241084008904248b44}
progress: 1%


Installing Rust
---------------
https://rustup.rs/


Python verison
--------------
check py/ folder


