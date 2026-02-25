# scrcpy Security Audit Report

**Date:** 2026-02-25
**Scope:** Full codebase (C client, Java server, build scripts)
**Branch:** `claude/security-audit-eAkO1`

---

## Executive Summary

This audit examines the scrcpy codebase for security vulnerabilities and unsupported/deprecated code patterns. The codebase is generally well-written with good security practices in many areas (e.g., `snprintf` over `sprintf`, `validate_string()` for shell parameter sanitization, proper null-checks after allocations). However, several issues were identified ranging from a critical protocol parsing bug to medium-severity concerns around Windows command construction and deprecated API usage.

**Findings Summary:**
- **Critical:** 1
- **High:** 4
- **Medium:** 11
- **Low:** 7

---

## Critical Findings

### 1. CRITICAL: Inverted Bounds Check in UHID Output Message Parsing

**File:** `app/src/device_msg.c:56`

```c
size_t size = sc_read16be(&buf[3]);
if (size < len - 5) {   // BUG: should be size > len - 5
    return 0; // not available
}
```

**Description:** The bounds check for `DEVICE_MSG_TYPE_UHID_OUTPUT` is inverted. The condition `size < len - 5` should be `size > len - 5`. As written, the check passes when `size` is *larger* than the available buffer and fails when the data actually fits. This means:
- When a complete message is available (`size <= len - 5`), it incorrectly returns 0 ("not available")
- When the message claims more data than is available (`size > len - 5`), it proceeds to `memcpy` with an out-of-bounds read from `buf`

This is a **heap buffer over-read** exploitable by a malicious device/server sending a crafted UHID output message with a `size` field larger than the remaining buffer. A compromised Android device could use this to crash the client or potentially leak memory contents.

**Fix:**
```c
if (size > len - 5) {
    return 0; // not available
}
```

---

## High Findings

### 2. HIGH: Windows Command Line Injection via Unescaped Arguments

**File:** `app/src/sys/win/process.c:13-24`

```c
static bool
build_cmd(char *cmd, size_t len, const char *const argv[]) {
    // Windows command-line parsing is WTF:
    // only make it work for this very specific program
    // (don't handle escaping nor quotes)
    size_t ret = sc_str_join(cmd, argv, ' ', len);
    ...
}
```

**Description:** On Windows, the command-line is constructed by joining arguments with spaces, with no escaping or quoting. The code explicitly acknowledges this limitation in comments. The `validate_string()` function in `server.c:190-202` blocks shell metacharacters for server parameters, but other argument sources (device serial from ADB, file paths from drag-and-drop in `file_pusher.c`, `SCRCPY_SERVER_PATH` environment variable) are NOT validated through `validate_string()`.

A crafted device serial number (e.g., from `adb devices`) or a file path containing special characters could inject additional command-line arguments when `adb` is invoked on Windows.

**Fix:** Implement proper Windows command-line escaping per Microsoft's conventions (quote arguments containing spaces, escape embedded quotes) in `build_cmd()`, or validate all external strings before passing them to `sc_adb_execute()`.

### 3. HIGH: Fixed-Size Command Buffer Without Overflow Protection

**File:** `app/src/server.c:212`

```c
const char *cmd[128];
unsigned count = 0;
cmd[count++] = sc_adb_get_executable();
// ... up to 50+ ADD_PARAM calls ...
```

**Description:** The `cmd` array in `execute_server()` has a fixed size of 128 entries. While current code uses approximately 50-60 slots maximum, there is no runtime bounds checking before `cmd[count++]`. If future development adds more parameters (or if parameters are added conditionally in a way that wasn't anticipated), this could overflow the stack buffer. The `ADD_PARAM` macro increments `count` without checking against the array bound.

**Fix:** Add a bounds check in the `ADD_PARAM` macro:
```c
#define ADD_PARAM(fmt, ...) do { \
    if (count >= ARRAY_LEN(cmd) - 1) { \
        LOGE("Too many server parameters"); \
        goto end; \
    } \
    ...
```

### 4. HIGH: Potential Integer Overflow in `sc_str_to_hex_string`

**File:** `app/src/util/str.c:360`

```c
char *
sc_str_to_hex_string(const uint8_t *data, size_t size) {
    size_t buffer_size = size * 3 + 1;
    char *buffer = malloc(buffer_size);
```

**Description:** If `size` is very large (e.g., `SIZE_MAX / 2`), the multiplication `size * 3` can wrap around to a small value due to integer overflow. This would cause `malloc` to allocate a small buffer, and the subsequent `snprintf` loop would write far beyond the allocated memory, causing heap corruption. While the current callers pass bounded sizes (e.g., UHID data with `uint16_t` size), the function itself has no protection.

**Fix:** Add an overflow check:
```c
if (size > (SIZE_MAX - 1) / 3) {
    LOG_OOM();
    return NULL;
}
```

### 5. HIGH: Missing `break` Statement in Java Options Parser (Fall-Through Bug)

**File:** `server/src/main/java/com/genymobile/scrcpy/Options.java:413-419`

```java
case "audio_encoder":
    if (!value.isEmpty()) {
        options.audioEncoder = value;
    }
case "power_off_on_close":   // <-- Missing break! Falls through!
    options.powerOffScreenOnClose = Boolean.parseBoolean(value);
    break;
```

**Description:** There is a missing `break` statement after the `"audio_encoder"` case. Whenever `audio_encoder` is set, execution falls through to `power_off_on_close`, causing `powerOffScreenOnClose` to be set to `Boolean.parseBoolean(audioEncoderValue)` (always `false` since an encoder name is never `"true"`). This silently overrides the user's `power_off_on_close` setting whenever an audio encoder is specified. This is a confirmed real bug.

**Fix:** Add `break;` after line 416.

---

## Medium Findings

### 5. MEDIUM: Incomplete Shell Character Validation

**File:** `app/src/server.c:190-202`

```c
static bool
validate_string(const char *s) {
    if (strpbrk(s, " ;'\"*$?&`#\\|<>[]{}()!~\r\n")) {
        LOGE("Invalid server param: [%s]", s);
        return false;
    }
    return true;
}
```

**Description:** The blocklist approach to shell character sanitization is fragile - it may miss characters that are special in certain shell contexts or locales. The comment acknowledges this is a workaround because arguments aren't properly escaped on Windows. Additionally, the validation is only applied to user-provided string parameters (codec options, encoder names, etc.) but not to all strings that flow into the command line.

Characters potentially missing: `%` (Windows batch), `^` (Windows escape), tab, form-feed.

**Fix:** Consider an allowlist approach instead (only permit `[a-zA-Z0-9_.,:=-]`).

### 6. MEDIUM: Clipboard Data from Device Not Sanitized

**File:** `app/src/receiver.c:45-61`

```c
static void
task_set_clipboard(void *userdata) {
    char *text = userdata;
    ...
    SDL_SetClipboardText(text);
    free(text);
}
```

**Description:** The clipboard text received from the Android device is set directly to the host clipboard without any sanitization. A compromised device could inject arbitrary content (including very large strings or strings with control characters) into the host clipboard. While this is inherent to scrcpy's clipboard sync feature, the lack of any size limit or content filtering means a malicious device could fill host memory or inject misleading content.

**Fix:** Add a maximum length check and optionally strip non-printable control characters (except newline/tab).

### 7. MEDIUM: Demuxer Accepts Zero-Length Packets Without Validation

**File:** `app/src/demuxer.c:109-110`

```c
uint32_t len = sc_read32be(&header[8]);
assert(len);
```

**Description:** The packet length from the network is only validated by an `assert()` which is compiled out in release builds (`-DNDEBUG`). In release mode, a zero-length packet would cause `av_new_packet(packet, 0)` to be called, and a very large `len` value (up to 4GB) would cause an allocation of that size. There is no upper-bound check on `len`.

**Fix:** Replace the assert with a proper runtime check:
```c
if (len == 0 || len > SC_PACKET_MAX_SIZE) {
    LOGE("Invalid packet size: %" PRIu32, len);
    return false;
}
```

### 8. MEDIUM: `process_msg` Static Buffer in Multi-Threaded Context

**File:** `app/src/controller.c:129`

```c
static bool
process_msg(struct sc_controller *controller,
            const struct sc_control_msg *msg, bool *eos) {
    static uint8_t serialized_msg[SC_CONTROL_MSG_MAX_SIZE];
```

**Description:** The `serialized_msg` buffer is declared `static` (shared across calls). While `process_msg` is currently only called from the single controller thread, this is fragile: any future change that calls `process_msg` from a second thread would cause a data race with no compiler or runtime warning. `SC_CONTROL_MSG_MAX_SIZE` is 256KB, which is large for a stack allocation but manageable.

**Fix:** Consider making this thread-local (`_Thread_local`) or a member of the controller struct.

### 9. MEDIUM: Deprecated FFmpeg API Usage (`channel_layout`, `channels`)

**File:** `app/src/demuxer.c:206-207`

```c
#else
    codec_ctx->channel_layout = AV_CH_LAYOUT_STEREO;
    codec_ctx->channels = 2;
#endif
```

**Description:** The `channel_layout` and `channels` fields on `AVCodecContext` are deprecated since FFmpeg 5.1 in favor of `ch_layout`. The code has a compile-time check (`SCRCPY_LAVU_HAS_CHLAYOUT`) for the new API, but the old path will eventually be removed from FFmpeg, requiring continuous maintenance. Other deprecated FFmpeg patterns may exist depending on the version compiled against.

**Impact:** Build failures with future FFmpeg versions that remove these deprecated fields.

### 10. MEDIUM: Deprecated SDL2 `channel_layout` Compatibility

**File:** `app/src/audio_player.c` (via conditional compilation)

**Description:** Similar to the FFmpeg issue, the audio player code maintains compatibility paths for older SDL2 APIs. As SDL3 is now available and SDL2 enters maintenance mode, these paths represent technical debt.

### 11. MEDIUM: `ANDROID_SERIAL` Environment Variable Used Without Validation

**File:** `app/src/server.c:984`

```c
const char *env_serial = getenv("ANDROID_SERIAL");
if (env_serial) {
    LOGI("Using ANDROID_SERIAL: %s", env_serial);
    selector.type = SC_ADB_DEVICE_SELECT_SERIAL;
    selector.serial = env_serial;
}
```

**Description:** The `ANDROID_SERIAL` environment variable is read and used as a device serial without validation. This value is later passed as a `-s` argument to `adb`. On Windows (due to the command-line injection issue), a malicious `ANDROID_SERIAL` value could inject additional arguments. On Unix, since arguments are passed as an array (not a string), this is less critical but could still cause unexpected behavior.

### 12. MEDIUM: Unbounded Byte Array Allocation from Network in Java Server

**File:** `server/src/main/java/com/genymobile/scrcpy/control/ControlMessageReader.java:91-96`

```java
private byte[] parseByteArray(int sizeBytes) throws IOException {
    int len = parseBufferLength(sizeBytes);
    byte[] data = new byte[len];
    dis.readFully(data);
    return data;
}
```

**Description:** `parseBufferLength` reads a length prefix from the network stream (up to 4 bytes for `parseString()`, so up to `Integer.MAX_VALUE`). The resulting `len` is used directly in `new byte[len]` without any upper-bound check. While constants like `CLIPBOARD_TEXT_MAX_LENGTH` (262130) and `INJECT_TEXT_MAX_LENGTH` (300) exist, they are NOT enforced in `parseByteArray`. A malicious client can crash the server by sending a very large length value, triggering `OutOfMemoryError`.

**Fix:** Add bounds checking in `parseByteArray`:
```java
if (len < 0 || len > MESSAGE_MAX_SIZE) {
    throw new IOException("Invalid buffer length: " + len);
}
```

### 13. MEDIUM: No Authentication on Unix Domain Socket (Java Server)

**File:** `server/src/main/java/com/genymobile/scrcpy/device/DesktopConnection.java:41-44`

**Description:** The server creates/connects to an abstract Unix domain socket with no authentication or peer credential verification. Any process on the Android device with the same UID or root access could connect and send control commands (inject input, read clipboard, create UHID devices, start/stop apps). In normal operation this is mitigated by ADB tunneling, but if the server is started without tunnel-forward mode, any local process could connect.

**Fix:** Consider implementing peer credential verification using `LocalSocket.getPeerCredentials()`.

### 14. MEDIUM: UHID Device Creation Without Input Validation (Java Server)

**File:** `server/src/main/java/com/genymobile/scrcpy/control/UhidManager.java:51-53`

**Description:** The UHID manager opens `/dev/uhid` to create virtual HID devices from client instructions. There is no validation of `vendorId`, `productId`, or `reportDesc` content/size. A malicious client could create arbitrary HID devices with any identity. Linux `UHID_DATA_MAX` is 4096 bytes; the report descriptor is not validated against this limit.

**Fix:** Validate report descriptor size against `UHID_DATA_MAX` and limit concurrent UHID devices.

### 15. MEDIUM: `sc_str_list_contains` Substring Match Bug

**File:** `app/src/util/str.c:177`

```c
if (!strncmp(list, s, token_len)) {
    return true;
}
```

**Description:** This comparison checks if the token in the list has `s` as a prefix, but doesn't verify that `s` is exactly `token_len` characters long. For example, searching for "ab" in "abc,def" would match "abc" because `strncmp("abc", "ab", 3)` compares only 3 chars of "abc" against "ab" — but actually `strncmp` stops at the shorter string's NUL byte. However, searching for "abc" in "ab,def" **would** incorrectly match "ab" because `strncmp("ab", "abc", 2)` only compares 2 characters. This is a logic bug that could cause false-positive matches.

**Fix:**
```c
if (token_len == strlen(s) && !strncmp(list, s, token_len)) {
```

---

## Low Findings

### 16. LOW: Assert-Only Validation in Multiple Locations

**Files:** Multiple (`server.c`, `demuxer.c`, `controller.c`)

**Description:** Several important invariant checks use `assert()` which is compiled out in release builds. Critical checks (especially on data from the network or device) should use proper runtime validation:
- `demuxer.c:110`: `assert(len)` on network packet size
- `server.c:1056`: `assert(r == sizeof(SC_SOCKET_NAME_PREFIX) - 1 + 8)` on format output

### 17. LOW: `ADB` Environment Variable Path Injection

**File:** `app/src/adb/adb.c:33`

```c
adb_executable = sc_get_env("ADB");
```

**Description:** The `ADB` environment variable allows overriding the adb binary path. While this is intentional and documented, it means a local attacker with the ability to set environment variables can redirect adb execution to an arbitrary binary. This is standard Unix behavior for development tools but worth noting for security-sensitive deployments.

### 18. LOW: Missing Error Propagation in `sc_str_wrap_lines`

**File:** `app/src/util/str.c:254`

```c
if (!sc_strbuf_init(&buf, cap)) {
    return false;  // BUG: function returns char*, not bool
}
```

**Description:** The function returns `false` (which is `0`/`NULL`) when the strbuf initialization fails, but the return type is `char *`. While `false` equals `NULL` in practice, this is a type mismatch that could cause confusion and indicates the error path wasn't carefully tested.

### 19. LOW: Shell Script Quoting Issues

**File:** `install_release.sh`, `bump_version`

**Description:** The shell scripts generally use proper quoting, but `install_release.sh` and `bump_version` could benefit from `set -euo pipefail` to catch errors early and prevent undefined variable expansion.

### 20. LOW: Missing `UHID_OUTPUT` Memory Leak on OOM Path

**File:** `app/src/receiver.c:130-133`

```c
struct sc_uhid_output_task_data *data = malloc(sizeof(*data));
if (!data) {
    LOG_OOM();
    return;  // msg->uhid_output.data is leaked
}
```

**Description:** When `malloc` fails for the task data struct, the function returns without freeing `msg->uhid_output.data`. The `process_msg` function takes ownership of the message data, but this OOM path fails to call `sc_device_msg_destroy(msg)`, leaking the UHID output data buffer.

**Fix:** Add `sc_device_msg_destroy(msg);` before `return;`.

### 21. LOW: Deprecated Android APIs in Java Server (ActivityManagerNative, SurfaceControl)

**Files:** `server/src/main/java/com/genymobile/scrcpy/wrappers/ActivityManager.java:33-36`, `SurfaceControl.java:40-53`

**Description:** The server uses `ActivityManagerNative.getDefault()` (removed in newer Android) and `SurfaceControl.openTransaction()`/`closeTransaction()` (deprecated in Android 14+). These are accessed via reflection so they fail at runtime rather than compile time. The code does not have fallback paths for all deprecated APIs.

### 22. LOW: Missing `UHID_OUTPUT` Memory Cleanup on Early Return

**File:** `app/src/receiver.c:125-127`

```c
if (!receiver->uhid_devices) {
    LOGE("Received unexpected HID output message");
    sc_device_msg_destroy(msg);
    return;
}
```

**Description:** When a UHID output message arrives but `uhid_devices` is NULL, the message is destroyed and the function returns. However, later in the function (line 141), data ownership is transferred. The early return path correctly calls `sc_device_msg_destroy`, but if future refactoring changes the ownership model, this could introduce a leak or double-free. This is defensive code quality rather than a current bug.

---

## Deprecated / Unsupported Code Summary

| Category | Item | Location | Replacement | Guarded? |
|----------|------|----------|-------------|----------|
| FFmpeg | `av_register_all()` (deprecated FFmpeg 4.0) | `main.c:72` | No-op in modern FFmpeg, remove call | Yes (`#ifdef`) |
| FFmpeg | `av_oformat_next()` (deprecated FFmpeg 4.0) | `recorder.c:33`, `v4l2_sink.c:27` | `av_muxer_iterate()` | Yes (`#ifdef`) |
| FFmpeg | `channels`, `channel_layout` fields (deprecated FFmpeg 5.1) | `demuxer.c:206`, `audio_player.c:40` | `ch_layout` (AVChannelLayout) | Yes (`#ifdef`) |
| FFmpeg | `av_opt_set_channel_layout()` (deprecated FFmpeg 5.1) | `audio_regulator.c:379` | `av_opt_set_chlayout()` | Yes (`#ifdef`) |
| FFmpeg | `av_stream_new_side_data()` (deprecated FFmpeg 6.1) | `recorder.c:524` | `av_packet_side_data_new()` | Yes (`#ifdef`) |
| FFmpeg | `AVFormatContext.filename` (deprecated FFmpeg 4.0) | `v4l2_sink.c:202` | `AVFormatContext.url` | Yes (`#ifdef`) |
| SDL | SDL2 threading/surface APIs | `thread.c`, `icon.c` | SDL3 equivalents (renamed APIs) | N/A |
| Android | `Looper.prepareMainLooper()` (deprecated API 30) | `Workarounds.java:90` | No replacement (necessary workaround) | No |
| Android | `SurfaceControl.openTransaction()` (deprecated API 28) | `SurfaceControl.java:40`, `ScreenCapture.java:205` | `SurfaceControl.Transaction` class | Version-gated |
| Android | Hidden/private API usage (`@SuppressLint`) | 9 wrapper classes | At risk of being blocked in future Android | **HIGH RISK** |
| Android | `android.support.test` runner | `server/build.gradle:12` | `androidx.test.runner.AndroidJUnitRunner` | No |
| Build | `meson_options.txt` filename (deprecated Meson 1.1) | `meson_options.txt` | Rename to `meson.options` | No |
| Build | Min FFmpeg req >= 57.33 (FFmpeg 3.1, 2016) | `app/meson.build:116` | Raise to >= 58.9 to drop 6 compat paths | No |
| Build | `proguard-android.txt` (deprecated) | `server/build.gradle:17` | `proguard-android-optimize.txt` | No |
| Platform | `WSAStartup(MAKEWORD(1, 1))` (WinSock 1.1) | `net.c:29` | `MAKEWORD(2, 2)` for WinSock 2.2 | No |
| Platform | `WINVER=0x0600` (Windows Vista target) | `app/meson.build:81` | `0x0601` (Win 7) or `0x0A00` (Win 10) | No |

---

## Positive Security Observations

The codebase demonstrates several good security practices:

1. **Consistent use of `snprintf`** over `sprintf` throughout
2. **Proper null-checks** after nearly all `malloc`/`strdup`/`asprintf` calls
3. **Shell metacharacter validation** via `validate_string()` for server parameters
4. **Proper resource cleanup** in error paths (goto-based cleanup in C)
5. **Network data parsing** with length checks before reads (in `device_msg.c`, except the inverted check)
6. **ADB arguments passed as arrays** on Unix (not concatenated strings), preventing shell injection
7. **Thread safety** with proper mutex usage around shared state
8. **Interrupt-safe socket operations** preventing blocking on shutdown

---

## Recommendations Priority

1. **Fix the inverted bounds check** in `device_msg.c:56` (Critical — can be exploited by malicious device)
2. **Fix missing `break` statement** in `Options.java:416` (High — confirmed real bug)
3. **Add proper Windows argument escaping** in `sys/win/process.c` (High)
4. **Add bounds check** on `cmd[]` array in `execute_server()` (High)
5. **Add integer overflow check** in `sc_str_to_hex_string()` (High)
6. **Add bounds checking** in Java `ControlMessageReader.parseByteArray()` (Medium — DoS via OOM)
7. **Replace `assert`** with runtime checks for network-derived values (Medium)
8. **Fix `sc_str_list_contains`** substring matching logic (Medium)
9. **Add allowlist validation** for shell parameters (Medium)
10. **Fix memory leak** in `receiver.c` OOM path for UHID output (Low)
11. **Raise minimum FFmpeg version** to >= 58.9 to eliminate 6 deprecated API compat paths (Medium)
12. **Plan SDL3 migration** — all SDL2 threading/surface wrappers need renaming (Medium, future)
13. **Add fallback paths** for deprecated Android APIs in Java wrappers (Low)
14. **Update build config** — rename `meson_options.txt`, update WinSock to 2.2, update ProGuard config (Low)
