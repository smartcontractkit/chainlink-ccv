package devenv_common

/*
This package contains common types for CCIPv1.7
Since 1.6/1.7 CCIP versions are incompatible for the time being we'll have 2 sets of interfaces that are mostly common
but exist in multiple repositories: chainlink-ccip (1.6) and chainlink-ccv (1.7)
*/

type (
	// UserMsg is a common CCIP message payload type, message format exposed to user is the same
	// however, different implementations may wrap it according to network standards.
	UserMsg       struct{}
	CommonAddress struct{}
	CommonMsgID   struct{}

	// CCIPMessageSentEvent common on-chain event payload for "CCIPMessageSent".
	CCIPMessageSentEvent struct{}
	// ExecutionStateChangedEvent common on-chain event payload for "ExecutionStateChanged".
	ExecutionStateChangedEvent struct{}
)
