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
