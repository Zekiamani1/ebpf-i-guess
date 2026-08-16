# eBPF  (Alpine Linux)

Diuji di **alpine-virtual** setelah menginstall `linux-lts`.

## Requirement

```sh
apk add clang llvm libbpf-dev bpftool linux-headers gcc musl-dev make linux-lts
```

Kernel butuh `CONFIG_DEBUG_INFO_BTF=y` dan `CONFIG_BPF_LSM=y` (sudah ada di `linux-lts` Alpine).

## Aktifkan BPF LSM

Wajib untuk `--ratelimit`. Tambahkan `lsm=` ke cmdline di `/etc/update-extlinux.conf`:

```
default_kernel_opts="... lsm=lockdown,capability,bpf"
```

lalu:

```sh
update-extlinux && reboot
```

Cek: `cat /sys/kernel/security/lsm` harus memuat `bpf`.

## Build

```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
make
```

## Run (butuh root)

```sh
./main          # run default
./main --usage  # baca cara bapakai
```

Output counter per-CPU ke stdout, detailnya ke file log:
`syscall.log`, `context_switch.log`, `fault.log`, `syscall_write.log`.
