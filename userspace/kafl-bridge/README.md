# kafl-bridge -- kAFL Frontend for Phantom

Python adapter that translates kAFL's agent interface to Phantom ioctls.

## kAFL ABI Mapping

| kAFL Hypercall | Phantom Equivalent |
|---|---|
| `KAFL_GET_PAYLOAD` (0x11a) | Payload written to shared_mem before `RUN_ITERATION` |
| `KAFL_ACQUIRE` (0x11c) | `PHANTOM_SET_SNAPSHOT` |
| `KAFL_RELEASE` (0x11d) | Iteration end (`RUN_ITERATION` returns with `RESULT_OK`) |
| `KAFL_PANIC` (0x11e) | `RESULT_CRASH` or `RESULT_PANIC` |
| `KAFL_KASAN` (0x11f) | `RESULT_KASAN` |

## Usage

```bash
# Basic run with random payloads
python3 phantom_bridge.py --max-iterations 1000 --payload-size 256

# Run with seed corpus
python3 phantom_bridge.py --corpus-dir ./seeds --crash-dir ./crashes

# Pin to CPU 2, 5000 iterations, verbose output
python3 phantom_bridge.py --cpu 2 --max-iterations 5000 --verbose
```

## Requirements

- Python 3.8+
- `phantom.ko` loaded (`kvm_intel` must be unloaded first)
- `/dev/phantom` accessible (root or appropriate permissions)

## Files

- `phantom_ioctl.py` -- ctypes ioctl wrappers for all Phantom ioctls
- `phantom_bridge.py` -- main kAFL-compatible fuzzing loop
- `requirements.txt` -- no external dependencies
