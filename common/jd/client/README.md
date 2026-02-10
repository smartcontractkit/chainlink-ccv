# client

Package `client` provides the **node-side client** for the [Job Distributor (JD)](https://docs.jd.cldev.sh/). It is used by operators (e.g. standalone CCV or executor nodes) that receive work from JD.

## Role

- **Connect** to JD over WSRPC with mTLS (Ed25519: node CSA signer + JD public key).
- **Receive** job lifecycle events from JD and expose them as Go channels:
  - **JobProposalCh** — new or replacement job proposals (id, version, spec).
  - **DeleteJobCh** — requests to delete the current job.
  - **RevokeJobCh** — revoke requests (e.g. for proposals not yet approved).
- **Send** responses back to JD: `ApproveJob`, `RejectJob`, `CancelJob`.

Consumers (e.g. the [lifecycle](../lifecycle) manager) typically connect the client, then read from these channels and call `ApproveJob` (or reject/cancel) as they process jobs. The client does not interpret job specs or run jobs; it only handles the protocol with JD.
