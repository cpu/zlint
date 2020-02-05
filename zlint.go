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

// Used to check parsed info from certificate for compliance

package zlint

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/lint"
	_ "github.com/zmap/zlint/lints/apple"
	_ "github.com/zmap/zlint/lints/cabf_br"
	_ "github.com/zmap/zlint/lints/cabf_ev"
	_ "github.com/zmap/zlint/lints/community"
	_ "github.com/zmap/zlint/lints/etsi"
	_ "github.com/zmap/zlint/lints/mozilla"
	_ "github.com/zmap/zlint/lints/rfc"
)

// LintCertificate runs all registered lints on c, producing a ResultSet.
//
// Using LintCertificate(c) is convenience equivalent to calling
// lint.DefaultLinter().Lint(c)
func LintCertificate(c *x509.Certificate) *lint.ResultSet {
	return lint.DefaultLinter().Lint(c)
}
