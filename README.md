# gsocket-config-extract

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)

Extract the operator configuration embedded in a **gsocket / gs-netcat** binary.

The `beta` branch of [gsocket](https://github.com/hackerschoice/gsocket) can store a
664-byte `struct gsnc_config` at the end of its own executable. At run time
`GSNC_config_read()` seeks to `SEEK_END - 664`, XORs the block with `0xAB`, and
checks an 8-byte magic. Deployments made with `deploy.sh` bake the operator's
relay, secret and masquerade name into that block — the highest-value indicators
in a gsocket intrusion.

## Install

```sh
git clone https://github.com/<you>/gsocket-config-extract
cd gsocket-config-extract
```

No dependencies. Python 3.8+ standard library only.

## Usage

```sh
python3 gsocket_config.py gs-netcat-suspect
```

```
[*] gs-netcat-suspect
    sha256 89e906327d8e85067e16f3eb077a4a891fd01773460363b235918035314703ea
[+] config found at offset 0x108AE8

    host (GSRN relay)    103.253.27.96
    port                 443
    secret               4jkuTMcyat7L6eAGJCn93t
    proc_hiddenname      [kthreadd]
    flags                0x00480140  OPT_DAEMON | OPT_QUIET | REEXEC | MEMEXEC
```

| Flag | Meaning |
|---|---|
| `--json` | machine-readable output (adds file path and sha256) |
| `--raw PATH` | also dump the decoded 664-byte blob |

Exit status is `1` when no config is present, so it drops straight into a triage loop:

```sh
find /suspect -type f -exec python3 gsocket_config.py {} \; 2>/dev/null
```

## Use the packed file

The config is appended **after** UPX packing, so it lives at the end of the
*packed* binary. Unpacking first discards it. If the sample arrived as a
bincrypter shell script, extract the ELF first (e.g. with
[bincrypter-extract](https://github.com/<you>/bincrypter-extract)) and run this
tool on that ELF — do **not** unpack it.

## Layout

`struct gsnc_config`, from `tools/gsnc-utils.h`:

| Offset | Field | Notes |
|---|---|---|
| `0x000` | `char host[128]` | GSRN relay; empty means the default `gs.thc.org` |
| `0x080` | `char proc_hiddenname[64]` | argv[0] the implant masquerades as; default `-bash ` |
| `0x0C0` | `uint16_t port` | |
| `0x0C4` | `int callhome_sec` | beacon interval |
| `0x0C8` | `int start_delay_sec` | |
| `0x0CC` | `uint32_t flags` | `GSC_FL_*` from `tools/common.h`, decoded by this tool |
| `0x0D0` | `char sec_str[64]` | **the gsocket secret** |
| `0x110` | `char shell[64]` | |
| `0x150` | `char domain[64]` | |
| `0x190` | `char workdir[64]` | |
| `0x1D0` | `char systemd_argv_match[64]` | |
| `0x210` | `char bail[128]` | command run if the GSRN is unreachable |
| `0x290` | `char magic[8]` | `"8xKd12TX" ^ 0x1F` |

The magic is XORed twice — `0x1F` when the field is written, then `0xAB` over the
whole struct — so on disk it reads `8C CC FF D0 85 86 E0 EC` (`"8xKd12TX" ^ 0xB4`).
That byte string at `filesize-8` is a reliable carving signature.

The tool checks the tail first, then falls back to scanning the whole file for the
magic, so it still finds configs in samples with trailing data appended.

## Safety

Pure parsing — the sample is never executed and nothing is written unless `--raw`
is given.

## License

MIT — see [LICENSE](LICENSE).
