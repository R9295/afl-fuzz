Rewrite of afl-fuzz in Rust.

To test:
1. Install afl++ / afl-cc
2. cargo build
3. afl-cc ./test/program.c -o ./program
4. ./target/debug/afl-fuzz ./program -i ./test/corpus -o ./crashes
