# CVEHunt Isolation Policy

CVEHunt must run vulnerability validation only inside authorized, disposable target environments. The target isolation backend should match the vulnerability class; Docker is useful for many userland package CVEs, but it is not a sufficient security boundary for kernel bugs, container escapes, or Kubernetes/node escapes.

## Backend Preference By Target Class

| Target class | Preferred isolation | Notes |
| --- | --- | --- |
| Userland package or web-service CVE | Docker/Compose in a disposable workspace or VM | Current implemented backend. Published ports must bind to `127.0.0.1` only. |
| Container image or runtime-adjacent app CVE | Docker/Compose inside a QEMU/KVM VM | Do not rely on the host Docker daemon as the final boundary. |
| Container escape, runc/containerd/Docker daemon CVE | QEMU/KVM VM running the container runtime under test | The escape target must be inside the VM, not on the contributor host. |
| Kubernetes escape or node-level CVE | QEMU/KVM-backed Kubernetes node VM(s) | `kind` alone is not enough unless it is nested inside a disposable VM boundary. |
| Kernel, eBPF, driver, filesystem, or namespace CVE | QEMU/KVM VM with snapshot/rollback | Never exercise kernel primitives on the contributor host. |
| Windows driver CVE | QEMU/KVM Windows guest with snapshot/rollback | Requires operator-supplied Windows image/ISO and driver installers. |
| Browser/client CVE | QEMU/KVM desktop VM with browser automation and snapshot/rollback | GUI or OS-specific targets need full VM tooling. |
| Firmware or architecture-specific CVE | QEMU full-system emulation or Icicle-style rehosting | Requires architecture, memory map, and firmware image inputs. |

## Open Source Backends

These options are open source and generally available, subject to host OS and hardware support:

- Docker / Docker Compose: container backend for userland app harnesses. Containers share the host kernel.
- QEMU/KVM: primary VM backend contract for Linux, Windows, container escape, Kubernetes-node, browser, and firmware-adjacent targets.
- Firecracker: Linux/KVM microVM backend with a small device model, strong fit for automated Linux harnesses.
- Cloud Hypervisor: lightweight KVM hypervisor for Linux guests.
- Kata Containers: runs containers inside lightweight VMs; useful when a container UX is desired with a VM boundary.
- kind/k3d: local Kubernetes cluster tooling; use inside a VM for escape testing rather than as the security boundary itself.

## Current Implementation

The current CVEHunt implementation supports Docker/Compose execution for local harnesses when `uv run cvehunt run ... --execute-poc` is set. It also emits QEMU-oriented target environment contracts for OS-bound targets, but full QEMU execution is not implemented yet. When a QEMU/manual target is missing kernels, root filesystems, Windows images, driver installers, firmware images, licenses, or setup notes, the run records `blocked_needs_artifact` and lists the exact required files.

Current Docker guarantees:

- generated services publish ports on `127.0.0.1` only;
- generated PoCs hardcode loopback targets;
- `SafetyPolicy.assert_localhost_scoped` rejects non-loopback PoC targets;
- Docker availability is checked before PoC execution;
- generated run artifacts preserve traces, reports, logs, and outcomes.

Current gaps:

- QEMU execution is represented as a setup contract and blocked-artifact state, not a full boot/probe implementation yet;
- Firecracker, Cloud Hypervisor, and Kubernetes VM-node backends are policy preferences, not implemented execution backends yet;
- Docker rootless/rootful status and host virtualization are recorded only by the contributor preflight, not enforced as a security boundary;
- dependency downloads during image build may require network unless the operator supplies cached/offline package mirrors;
- model-authored exploit/patch generation is not implemented yet; current runs record model attribution and deterministic pipeline output.

## Contributor Preflight

`./contribute.sh` performs an early isolation preflight before running the CVE workflow.

Environment variables:

- `CVEHUNT_ISOLATION_BACKEND=docker` selects the current Docker/Compose backend. This is the default and the only implemented execution backend today.
- `CVEHUNT_ISOLATION_BACKEND=firecracker` checks for `/dev/kvm`, `firecracker`, and `jailer`, then exits because Firecracker execution is not implemented yet.
- `CVEHUNT_ISOLATION_BACKEND=qemu` checks for `/dev/kvm` and `qemu-system-x86_64`, then exits because QEMU execution is not implemented yet.
- `CVEHUNT_ISOLATION_BACKEND=external-vm` records that the contributor claims the run is already inside a disposable VM and still checks Docker when `CVEHUNT_EXECUTE_POC=1`.
- `CVEHUNT_EXECUTE_POC=0` opts out of building and running the local harness PoC in `./contribute.sh`.

Every contributor run writes `isolation-preflight.log` plus `contribution_audit.{json,md}` into the run directory so downstream reviewers can see the selected backend, detected dependencies, and whether PoC execution was requested.
