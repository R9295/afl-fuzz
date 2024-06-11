Rewrite of afl-fuzz in Rust.

To test:
1. Install afl++ / afl-cc
2. cargo build
3. afl-cc ./test/program.c -o ./program
4. ./target/debug/afl-fuzz ./program -i ./test/corpus -o ./crashes


# TODO
- [x] AFL_HANG_TMOUT
- [x] AFL_NO_AUTODICT
- [x] AFL_MAP_SIZE
- [x] AFL_KILL_SIGNAL
- [x] AFL_BENCH_JUST_ONE
- [x] AFL_DEBUG_CHILD
- [x] AFL_PERSISTENT
- [x] AFL_IGNORE_TIMEOUTS
- [x] AFL_EXIT_ON_SEED_ISSUES
- [x] AFL_BENCH_UNTIL_CRASH
- [x] AFL_TMPDIR
- [x] AFL_CRASH_EXITCODE
- [x] AFL_TARGET_ENV
- [x] AFL_IGNORE_SEED_PROBLEMS (renamed to AFL_IGNORE_SEED_ISSUES)
- [x] AFL_CRASH_EXITCODE
- [x] AFL_INPUT_LEN_MIN
- [x] AFL_INPUT_LEN_MAX
- [ ] AFL_AUTORESUME
- [ ] AFL_CRASHING_SEEDS_AS_NEW_CRASH
- [ ] AFL_IGNORE_UNKNOWN_ENVS
- [ ] AFL_NO_UI
- [ ] AFL_NO_STARTUP_CALIBRATION
- [ ] AFL_PIZZA_MODE :)
- [ ] AFL_EXIT_WHEN_DONE
- [ ] AFL_EXIT_ON_TIME
- [ ] AFL_NO_AFFINITY
- [ ] AFL_FORKSERVER_KILL_SIGNAL
- [ ] AFL_NO_WARN_INSTABILITY
- [x] AFL_CYCLE_SCHEDULES
- [ ] AFL_EXPAND_HAVOC_NOW
- [ ] AFL_NO_STARTUP_CALIBRATION
- [ ] AFL_NO_FORKSRV
- [ ] AFL_FORKSRV_INIT_TMOUT
- [ ] AFL_CMPLOG_ONLY_NEW
- [ ] AFL_TRY_AFFINITY
- [ ] AFL_FAST_CAL
- [ ] AFL_NO_CRASH_README
- [ ] AFL_KEEP_TIMEOUTS
- [ ] AFL_PERSISTENT_RECORD
- [ ] AFL_FUZZER_STATS_UPDATE_INTERVAL
- [ ] AFL_TESTCACHE_SIZE
- [ ] AFL_NO_ARITH
- [ ] AFL_DISABLE_TRIM
- [ ] AFL_MAX_DET_EXTRAS
- [ ] AFL_SKIP_BIN_CHECK
- [ ] AFL_IGNORE_PROBLEMS
- [ ] AFL_IGNORE_PROBLEMS_COVERAGE
- [ ] AFL_STATSD_TAGS_FLAVOR
- [ ] AFL_STATSD
- [ ] AFL_STATSD_PORT
- [ ] AFL_STATSD_HOST
- [ ] AFL_IMPORT
- [ ] AFL_IMPORT_FIRST
- [ ] AFL_SYNC_TIME
- [ ] AFL_FINAL_SYNC
- [ ] AFL_SHUFFLE_QUEUE
- [ ] AFL_CUSTOM_QEMU_BIN
- [ ] AFL_PATH
- [ ] AFL_CUSTOM_MUTATOR_LIBRARY
- [ ] AFL_CUSTOM_MUTATOR_ONLY
- [ ] AFL_PYTHON_MODULE
- [ ] AFL_DEBUG
- [ ] AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES
- [ ] AFL_DUMB_FORKSRV
- [ ] AFL_PRELOAD
- [ ] AFL_DEFER_FORKSRV
- [ ] AFL_EARLY_FORKSERVER
- [ ] AFL_NO_SNAPSHOT
