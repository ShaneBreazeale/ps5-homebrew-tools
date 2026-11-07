# dev-control

Resident listener on TCP 9098. One authenticated command per connection:
list processes, stop one chosen app, or copy an existing screenshot file.
Firmware 13.60. This tree has not been console-validated.

The payload calls `kernel_get_fw_version()` and continues when
`(fw & 0xffff0000) == 0x13600000`. It does not read the SoC id. That call is
the only use of `<ps5/kernel.h>`. There are no kernel reads, kernel writes,
hooks, or debug-register changes. The listener does not open port 9021.

## Build and send

From the repository root, with `PS5_PAYLOAD_SDK` set:

```sh
make dev-control
mkdir -p captures
python3 host/send_payload.py out/dev-control.elf \
  --host "$PS5_HOST" --log captures/dev-control-001.log
```

`make all` includes this payload. The sender is the one-shot loader client.
The ready line is the first stdout line:

```text
dev-control: ready pid=<pid> port=9098 token=<64 lowercase hex>
```

The token is 32 bytes from `/dev/urandom`, printed once for that boot. It is
not stored in this repository. A failed read exits 1 before the port is
opened. Anyone who can read the ready line can send a command for the rest
of that boot; treat the token as a bearer credential.

After the ready line the process listens and prints nothing else. The
sender's default 60-second idle timeout then ends the log connection and
exits 2 with `Log connection idle; payload may still be running.` That exit
is expected. Do not resend. Copy the token from the log, then use
`host/dev_ctl.py` on TCP 9098. Whether the listener is still running after
the loader drops the log socket has not been checked on a console.

On any other firmware the payload prints `dev-control: unsupported firmware`
and returns 7.

## Host client

`--host` and `--token` are required. The client lowercases the token. `--port`
defaults to 9098. `--timeout` defaults to 30 seconds for the whole exchange,
including DNS. A text command succeeds when its last non-empty line starts
with `OK:`. Any `ERR:` result exits 1.

```sh
python3 host/dev_ctl.py --host "$PS5_HOST" --token "$DEV_CTL_TOKEN" ping
python3 host/dev_ctl.py --host "$PS5_HOST" --token "$DEV_CTL_TOKEN" list
python3 host/dev_ctl.py --host "$PS5_HOST" --token "$DEV_CTL_TOKEN" kill ACTIVE
python3 host/dev_ctl.py --host "$PS5_HOST" --token "$DEV_CTL_TOKEN" kill PPSA12345
python3 host/dev_ctl.py --host "$PS5_HOST" --token "$DEV_CTL_TOKEN" shot -o capture.jpg
```

## Commands

The listener accepts one line, then closes the connection. The deadline is
30 seconds from `accept`. A line that ends early, contains a NUL, or does
not fit in the buffer is ignored. A missing, wrong, or non-lowercase token
answers `ERR:AUTH` and performs no query, signal, or file read.

| Command | Result |
| --- | --- |
| `PING <token>` | `OK:PONG` |
| `LIST <token>` | One `proc` line per recorded process, then `OK:LIST n=<count>` |
| `KILL <token> <target>` | See below |
| `SHOT <token>` | `OK:SHOT png\|jpg <bytes>` and then the file bytes |

`LIST` uses the same 13.60 process-record offsets as process-snapshot: pid
72, ppid 76, stat 388, comm 447, thread count 596. Each record's stride must
be at least 600 bytes, with the thread-count field inside that record. A
short record or a short trailing fragment answers `ERR:QUERY_FAILED`. When
the list is longer than 512 processes, `LIST` prints the first 512 and the
OK line ends with `truncated`, for example `OK:LIST n=513 truncated`.

### KILL

`ACTIVE` asks `libSceSystemService.sprx` for the running big app and requests
a stop through `sceLncUtilKillApp` or `sceSystemServiceKillApp`. Success is
`OK:KILLED app=<id>`. That line means the system request returned success.
The payload does not wait for the process to exit. If the module is missing,
or both stop symbols are missing, the answer is `ERR:UNAVAILABLE`. If no
request succeeds, the answer is `ERR:NOT_FOUND`. `ACTIVE` stops there.

A target that starts with `PPSA` tries that system request first. If the
request does not succeed, the payload selects an exact title-id match from
the process list. A title is not a prefix match.

A numeric pid, or any other target, uses the process list. A numeric target
of `1` answers `ERR:REFUSED` before the query. `0` and an out-of-range number
answer `ERR:NOT_FOUND`. An exact `comm` or exact title matches; the payload's
own pid is skipped and is not a match. Matches are collected before any
signal. If any remaining match is pid 1, or its `comm` contains `Shell`,
`SceShell`, or `SysCore` as a case-sensitive substring, the answer is
`ERR:REFUSED` and no process is signaled. A truncated list answers
`ERR:TRUNCATED` and no process is signaled. A layout failure answers
`ERR:QUERY_FAILED`.

When every `kill()` succeeds the answer is `OK:KILLED pid=<first> count=<n>`.
When any `kill()` fails the answer is `ERR:PARTIAL killed=<n> failed=<m>`.
An empty target answers `ERR:EMPTY_TARGET`.

### SHOT

`SHOT` copies the newest usable file under `/user/av_contents/photo`. It
reads an existing file. The walk uses `lstat` and opens every path component
with `O_NOFOLLOW`, so a symlink is not followed. It recurses only into real
directories, three levels down, which reaches
`photo/<app>/<title>/<3-hex>/<file>.jpg`. A depth of zero does not descend.
Directory entries other than `.` and `..` count toward a cap of 8192. Regular
files whose names end in `.png`, `.jpg`, or `.jpeg` are candidates; `.jpeg`
is reported as `jpg`.

Candidates are ordered by modification time. If the newest cannot be opened,
is no longer a regular file, is empty, or is larger than 64 MiB, the next
newest is tried. When none remain, the answer is `ERR:NO_SCREENSHOT`.

The host rejects a declared size outside 1 byte through 64 MiB before it
reads a body. It writes the output with `O_CREAT|O_EXCL|O_WRONLY` (mode
`0600`) and refuses a path that already exists, including a symlink. Omit
`-o` to use `capture.png` or `capture.jpg` in the current directory.
