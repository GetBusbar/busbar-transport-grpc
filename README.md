<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
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

## Limits and failure handling

Message payloads obey `limits.request_body_max_bytes`. Across a connection,
partial incoming messages share a budget of that limit plus 1 MiB and 64 KiB;
a stream exceeding the budget fails with `RESOURCE_EXHAUSTED`. Requests awaiting
host admission and newly arrived requests each have a 200-request queue limit;
overflow receives HTTP 503, and peer resets release pending admission state.

Malformed message flags and invalid host refusals fail explicitly. Premature
status fields are removed from initial response headers so they cannot override
the final gRPC status.
Credential-bearing head buffers are wiped when released. A request whose host
marks `:path` sensitive is refused because this HTTP/2 client cannot mark its
request target as sensitive for header compression.

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
