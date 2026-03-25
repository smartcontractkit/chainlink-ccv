package common

const (
	// These qualifiers are used to distinguish between multiple deployments of the committee verifier proxy and mock receiver
	// on the same chain.
	// In the smoke test deployments these are the qualifiers that are used by default.
	DefaultCommitteeVerifierQualifier = "default"
	DefaultReceiverQualifier          = "default"
	DefaultExecutorQualifier          = "default"

	SecondaryCommitteeVerifierQualifier = "secondary"
	SecondaryReceiverQualifier          = "secondary"

	TertiaryCommitteeVerifierQualifier = "tertiary"
	TertiaryReceiverQualifier          = "tertiary"

	QuaternaryReceiverQualifier = "quaternary"

	CustomExecutorQualifier = "custom"

	CCTPPrimaryReceiverQualifier   = "cctp-primary"
	CCTPSecondaryReceiverQualifier = "cctp-secondary"

	LombardContractsQualifier       = "Lombard"
	LombardPrimaryReceiverQualifier = "lombard-primary"
)
