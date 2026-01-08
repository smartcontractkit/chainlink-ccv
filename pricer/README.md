## Pricer

Pricer is a standalone service for updating gas/token prices on various chains 
in CCIP 1.7. 

It aims to serve as the first concrete example of a product specific binary (PSB), i.e.
one that runs outside the core node. In particular to illustrate how:
- Dependencies on family specific Go modules like chainlink-evm/chainlink-solana etc.
can be used in a PSB, crucially including how TOML configuration for shared components
like chain read/write can be imported.
- Dependencies on family and product agnostic Go modules like chainlink-common and chainlink/keystore can be used in a PSB, crucially including how CLI logic can be shared/standardized 
across PSBs. 


## Generating Keys

The pricer binary includes an embedded keystore CLI for managing keys.

### 1. Create an empty keystore file

```bash
touch keystore.json
```

### 2. Set environment variables

```bash
export KEYSTORE_FILE_PATH=keystore.json
export KEYSTORE_PASSWORD=your-secure-password
```

### 3. Create an EVM transaction signing key

```bash
go run cmd/main.go keystore create -d '{"Keys": [{"KeyName": "pricer-tx-key", "KeyType": "ECDSA_S256"}]}'
```

### 4. List keys to verify

```bash
go run cmd/main.go keystore list
```

Output:
```json
{"Keys":[{"KeyName":"pricer-tx-key","KeyType":"ECDSA_S256","CreatedAt":"2026-01-08T...","PublicKey":"..."}]}
```

## Running the Service

### Local Development

```bash
# Set keystore env vars (base64-encoded keystore data)
export KEYSTORE_DATA=$(cat keystore.json | base64)
export KEYSTORE_PASSWORD=your-secure-password

# Run with just
just run

# Or run directly
go run cmd/main.go run --config config.example.toml
```

### Docker

```bash
# Build
just build

# Run (env vars must be set)
KEYSTORE_DATA=$(cat keystore.json | base64) KEYSTORE_PASSWORD=your-secure-password just run
```

### Kubernetes

In K8s, store the base64-encoded keystore and password as secrets:

```yaml
env:
  - name: KEYSTORE_DATA
    valueFrom:
      secretKeyRef:
        name: pricer-secrets
        key: keystore-data
  - name: KEYSTORE_PASSWORD
    valueFrom:
      secretKeyRef:
        name: pricer-secrets
        key: keystore-password
```
They will be encrypted with SOPS so they are passed securely to the service.