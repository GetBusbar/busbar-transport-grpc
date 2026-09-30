<!-- fleet:header:begin (rendered by `cargo xtask fleet render` from GetBusbar/busbar's plugins.yaml; edit it there) -->
# busbar-transport-grpc

First-party signed kind:transport plugin cdylib: the grpc transport, packaged as a droppable busbar plugin. Drop the signed tarball into plugins/.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `transport` | `grpc` | `busbar-transport-grpc-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-transport-grpc/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-transport-grpc/actions/workflows/ci.yml)
<!-- fleet:header:end -->

## What it is for

`busbar-transport-grpc` is a `kind: transport` busbar plugin.

## Config

Configured under the `grpc` module name.

## Build

```bash
cargo build --release -p busbar-transport-grpc-plugin
```

## Tests

```bash
cargo test --workspace --locked
```

## License

Apache-2.0. See [LICENSE](LICENSE).
