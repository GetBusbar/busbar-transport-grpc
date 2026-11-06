<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-transport-grpc

First-party signed kind:transport plugin cdylib: the grpc transport, packaged as a droppable busbar plugin. Drop the signed tarball into plugins/.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `transport` | `grpc` | `busbar-transport-grpc-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

<!-- fleet:header:end -->

## What it is for

`busbar-transport-grpc` is a `kind: transport` busbar plugin.

## Config

Configured under the `grpc` module name.

Settings (`transport-grpc/settings.schema.json`; unknown keys and `null` are refused):

| key | meaning | default |
|---|---|---|
| `limits.upstream_request_timeout_secs` | a dialled call's deadline when the host states none, in seconds (above 0) | `300` |
| `limits.request_body_max_bytes` | the largest message payload read from a far end, in bytes (above 0) | `33554432` |

## Limits and failure handling

Message payloads read from a far end obey `limits.request_body_max_bytes`. Across a connection,
partial incoming messages share a budget of that limit plus 1 MiB and 64 KiB;
a stream exceeding the budget fails with `RESOURCE_EXHAUSTED`. Requests awaiting
host admission and newly arrived requests each have a 200-request queue limit;
overflow receives HTTP 503, and peer resets release pending admission state.
Far-side bytes a connection has been handed and not yet read (its HTTP/2 machine stops reading
while a far end leaves what it is owed untaken) are reported as `framer.retained_input` on each
READY connection answer that completes its drive (not on a policy-open request, which is recalled
at once), so the host's receive backpressure counts them. A dialled connection pings an idle far
end every 5 minutes, no more often than gRPC servers permit by default.

A valid inbound `grpc-timeout` bounds each accepted call on the host monotonic
clock, including time awaiting admission. Expiry yields a stream failure and
closes with `DEADLINE_EXCEEDED`. The body-only adapter exposes the same timer
contract; its host must drive timers and cancel admitted work on stream failure.
When the host supplies a request deadline to `locate` in its CLOCK_NOW provider's
epoch, the framer declares a `grpc-timeout` default from the remaining budget before
authentication. An unavailable host clock fails preparation. The host retains an
explicit timeout field in preference to this default; the authenticated head is
preserved on emit, and the local attempt deadline remains independent.

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
