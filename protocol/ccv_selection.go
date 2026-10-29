package protocol

// SelectedCCVs is the ordered CCV selection the executor submits to execute(): all required CCVs,
// then the first OptionalThreshold optional CCVs that have a result, both in configured order.
type SelectedCCVs struct {
	Required []VerifierResult
	Optional []VerifierResult
	// MissingRequired is the first required CCV with no result. Required holds only the CCVs before it.
	MissingRequired *UnknownAddress
	// Complete is true if all required CCVs and at least OptionalThreshold optional CCVs were found.
	Complete bool
}

// SelectCCVsForExecution returns the CCV selection for execute() from the known verifier results,
// keyed by VerifierDestAddress.String(), and the destination CCV configuration.
func SelectCCVsForExecution(resultsByCCV map[string]VerifierResult, ccvAddressInfo CCVAddressInfo) SelectedCCVs {
	selected := SelectedCCVs{
		Required: make([]VerifierResult, 0, len(ccvAddressInfo.RequiredCCVs)),
		Optional: make([]VerifierResult, 0, ccvAddressInfo.OptionalThreshold),
	}

	for _, ccvAddress := range ccvAddressInfo.RequiredCCVs {
		result, found := resultsByCCV[ccvAddress.String()]
		if !found {
			missing := ccvAddress
			selected.MissingRequired = &missing
			return selected
		}
		selected.Required = append(selected.Required, result)
	}

	for _, ccvAddress := range ccvAddressInfo.OptionalCCVs {
		if len(selected.Optional) >= int(ccvAddressInfo.OptionalThreshold) {
			break
		}
		if result, found := resultsByCCV[ccvAddress.String()]; found {
			selected.Optional = append(selected.Optional, result)
		}
	}

	selected.Complete = len(selected.Optional) >= int(ccvAddressInfo.OptionalThreshold)
	return selected
}
