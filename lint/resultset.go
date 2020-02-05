/*
 * ZLint Copyright 2020 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package lint

import (
	"time"
)

const resultSetVersion int64 = 4

// ResultSet is a collection of LintResults and associated metadata. A ResultSet
// is generated when a Linter lints a certificate with its registered lints.
type ResultSet struct {
	Version            int64                  `json:"version"`
	NoticesPresent     bool                   `json:"notices_present"`
	WarningsPresent    bool                   `json:"warnings_present"`
	ErrorsPresent      bool                   `json:"errors_present"`
	FatalsPresent      bool                   `json:"fatals_present"`
	Results            map[string]*LintResult `json:"lints"`
	LintStartTimestamp int64                  `json:"timestamp"`
	LintEndTimestamp   int64                  `json:"end_timestamp"`
}

// newResultSet creates a ResultSet and populates the Version and
// LintStartTimestamp.
func newResultSet() *ResultSet {
	return &ResultSet{
		Version:            resultSetVersion,
		Results:            make(map[string]*LintResult),
		LintStartTimestamp: time.Now().Unix(),
	}
}

// AddResult adds the provided LintResult to the ResultSet, ensuring that
// NoticesPresent, WarningsPresent, ErrorsPresent, and FatalsPresent are updated
// according to the LintResult.Status.
func (rs *ResultSet) AddResult(lintName string, result *LintResult) {
	if rs.Results == nil {
		rs.Results = make(map[string]*LintResult)
	}
	rs.Results[lintName] = result

	if result != nil {
		switch result.Status {
		case Notice:
			rs.NoticesPresent = true
		case Warn:
			rs.WarningsPresent = true
		case Error:
			rs.ErrorsPresent = true
		case Fatal:
			rs.FatalsPresent = true
		}
	}
}

// Above returns a copy of the ResultSet Results that only includes lint results
// with a Status higher than the provided LintStatus.
func (rs *ResultSet) Above(status LintStatus) map[string]*LintResult {
	filteredResults := make(map[string]*LintResult, len(rs.Results))
	for name, res := range rs.Results {
		if res.Status > status {
			filteredResults[name] = res
		}
	}
	return filteredResults
}
