package evmconfig

import (
	"errors"
	"fmt"
	"sort"
)

func (n *Node) validate() error {
	var errs []error
	if n.HTTPUrl == "" {
		errs = append(errs, fmt.Errorf("field 'http_url' is required"))
	}
	if n.Order < 0 || n.Order > 100 {
		errs = append(errs, fmt.Errorf("field 'order' must be between 1 and 100 (or 0 to leave unset), got %d", n.Order))
	}
	return errors.Join(errs...)
}

func (c *ChainConfig) validate() error {
	var errs []error
	if len(c.Nodes) == 0 {
		errs = append(errs, fmt.Errorf("at least one node is required"))
	}
	for i := range c.Nodes {
		if err := c.Nodes[i].validate(); err != nil {
			errs = append(errs, fmt.Errorf("failed to validate node %d: %w", i, err))
		}
	}
	if c.SourceReaderHeaderFetchBatchSize < 0 {
		errs = append(errs, fmt.Errorf("field 'source_reader_header_fetch_batch_size' must not be negative"))
	}
	return errors.Join(errs...)
}

// Validate checks every chain, reporting all problems at once. Call it on the merged config, after
// secrets have supplied any node URLs.
func (c *Config) Validate() error {
	selectors := make([]string, 0, len(c.Chains))
	for selector := range c.Chains {
		selectors = append(selectors, selector)
	}
	sort.Strings(selectors)

	var errs []error
	for _, selector := range selectors {
		chain := c.Chains[selector]
		if err := chain.validate(); err != nil {
			errs = append(errs, fmt.Errorf("failed to validate chain %q: %w", selector, err))
		}
	}
	return errors.Join(errs...)
}
