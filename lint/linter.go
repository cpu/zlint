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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zmap/zcrypto/x509"
)

// FilterOptions is a struct used by Registry.Filter to create a sub registry
// containing only lints that meet the filter options specified.
//
// Source based exclusion/inclusion is evaluated before Lint name based
// exclusion/inclusion. In both cases exclusion is processed before inclusion.
//
// Only one of NameFilter or IncludeNames/ExcludeNames can be provided at
// a time.
type FilterOptions struct {
	// NameFilter is a regexp used to filter lints by their name. It is mutually
	// exclusive with IncludeNames and ExcludeNames.
	NameFilter *regexp.Regexp
	// IncludeNames is a case sensitive list of lint names to include in the
	// registry being filtered.
	IncludeNames []string
	// ExcludeNames is a case sensitive list of lint names to exclude from the
	// registry being filtered.
	ExcludeNames []string
	// IncludeSource is a SourceList of LintSource's to be included in the
	// registry being filtered.
	IncludeSources SourceList
	// ExcludeSources is a SourceList of LintSources's to be excluded in the
	// registry being filtered.
	ExcludeSources SourceList
}

// Empty returns true if the FilterOptions is empty and does not specify any
// elements to filter by.
func (opts FilterOptions) Empty() bool {
	return opts.NameFilter == nil &&
		len(opts.IncludeNames) == 0 &&
		len(opts.ExcludeNames) == 0 &&
		len(opts.IncludeSources) == 0 &&
		len(opts.ExcludeSources) == 0
}

// TODO(@cpu): Rewrite
type Linter interface {
	// Names returns a list of all of the lint names that have been registered
	// with the linter in string sorted order.
	Names() []string
	// Sources returns a SourceList of registered LintSources. The list is not
	// sorted but can be sorted by the caller with sort.Sort() if required.
	Sources() SourceList
	// Filter returns a new Linter containing only the registered lints that match
	// the FilterOptions criteria.
	Filter(opts FilterOptions) (Linter, error)
	// WriteJSON writes a description of each registered lint as
	// a JSON object, one object per line, to the provided writer.
	WriteJSON(w io.Writer)
	// TODO(@cpu): Doc Lint func in Linter interface
	Lint(c *x509.Certificate) *ResultSet
	// TODO(@cpu): Doc LintByName func in Linter interface
	LintByName(lintName string, c *x509.Certificate) *ResultSet
}

// linterImpl implements the Linter interface to provide a collection
// of Lints that can be used to lint a certificate.
type linterImpl struct {
	sync.RWMutex
	// lintsByName is a map of all registered lints by name.
	lintsByName map[string]*Lint
	// lintNames is a sorted list of all of the registered lint names. It is
	// equivalent to collecting the keys from lintsByName into a slice and sorting
	// them lexicographically.
	lintNames []string
	// lintsBySource is a map of all registered lints by source category. Lints
	// are added to the lintsBySource map by RegisterLint.
	lintsBySource map[LintSource][]*Lint
}

var (
	// errNilLint is returned from registry.Register if the provided lint was nil.
	errNilLint = errors.New("can not register a nil lint")
	// errNilLintPtr is returned from registry.Register if the provided lint had
	// a nil Lint field.
	errNilLintPtr = errors.New("can not register a lint with a nil Lint pointer")
	// errEmptyName is returned from registry.Register if the provided lint had an
	// empty Name field.
	errEmptyName = errors.New("can not register a lint with an empty Name")
)

// errDuplicateName is returned from registry.Register if the provided lint had
// a Name field matching a lint that was previously registered.
type errDuplicateName struct {
	lintName string
}

func (e errDuplicateName) Error() string {
	return fmt.Sprintf(
		"can not register lint with name %q - it has already been registered",
		e.lintName)
}

// errBadInit is returned from linterImpl.Register if the provided lint's
// Initialize function returned an error.
type errBadInit struct {
	lintName string
	err      error
}

func (e errBadInit) Error() string {
	return fmt.Sprintf(
		"failed to register lint with name %q - failed to Initialize: %q",
		e.lintName, e.err)
}

// register adds the provided lint to the Linter. If initialize is true then
// the lint's Initialize() function will be called before registering the lint.
//
// An error is returned if the lint or lint's Lint pointer is nil, if the Lint
// has an empty Name or if the Name was previously registered.
func (linter *linterImpl) register(l *Lint, initialize bool) error {
	if l == nil {
		return errNilLint
	}
	if l.Lint == nil {
		return errNilLintPtr
	}
	if l.Name == "" {
		return errEmptyName
	}
	if existing := linter.byName(l.Name); existing != nil {
		return &errDuplicateName{l.Name}
	}
	if initialize {
		if err := l.Lint.Initialize(); err != nil {
			return &errBadInit{l.Name, err}
		}
	}
	linter.Lock()
	defer linter.Unlock()
	linter.lintNames = append(linter.lintNames, l.Name)
	linter.lintsByName[l.Name] = l
	linter.lintsBySource[l.Source] = append(linter.lintsBySource[l.Source], l)
	sort.Strings(linter.lintNames)
	return nil
}

// byName returns the Lint previously registered under the given name with
// Register, or nil if no matching lint name has been registered.
func (l *linterImpl) byName(name string) *Lint {
	l.RLock()
	defer l.RUnlock()
	return l.lintsByName[name]
}

// Names returns a list of all of the lint names that have been registered
// in string sorted order.
func (l *linterImpl) Names() []string {
	l.RLock()
	defer l.RUnlock()
	return l.lintNames
}

// Sources returns a SourceList of registered LintSources. The list is not
// sorted but can be sorted by the caller with sort.Sort() if required.
func (l *linterImpl) Sources() SourceList {
	l.RLock()
	defer l.RUnlock()
	var results SourceList
	for k := range l.lintsBySource {
		results = append(results, k)
	}
	return results
}

// lintNamesToMap converts a list of lit names into a bool hashmap useful for
// filtering. If any of the lint names are not known by the registry an error is
// returned.
func (l *linterImpl) lintNamesToMap(names []string) (map[string]bool, error) {
	if len(names) == 0 {
		return nil, nil
	}

	namesMap := make(map[string]bool, len(names))
	for _, n := range names {
		n = strings.TrimSpace(n)
		if l.byName(n) == nil {
			return nil, fmt.Errorf("unknown lint name %q", n)
		}
		namesMap[n] = true
	}
	return namesMap, nil
}

func sourceListToMap(sources SourceList) map[LintSource]bool {
	if len(sources) == 0 {
		return nil
	}
	sourceMap := make(map[LintSource]bool, len(sources))
	for _, s := range sources {
		sourceMap[s] = true
	}
	return sourceMap
}

// Filter creates a new Linter with only the lints that meet the FilterOptions
// criteria included.
//
// FilterOptions are applied in the following order of precedence:
//   ExcludeSources > IncludeSources > NameFilter > ExcludeNames > IncludeNames
func (l *linterImpl) Filter(opts FilterOptions) (Linter, error) {
	// If there's no filtering to be done, return the existing Registry.
	if opts.Empty() {
		return l, nil
	}

	filteredLinter := newLinter()

	sourceExcludes := sourceListToMap(opts.ExcludeSources)
	sourceIncludes := sourceListToMap(opts.IncludeSources)

	nameExcludes, err := l.lintNamesToMap(opts.ExcludeNames)
	if err != nil {
		return nil, err
	}
	nameIncludes, err := l.lintNamesToMap(opts.IncludeNames)
	if err != nil {
		return nil, err
	}

	if opts.NameFilter != nil && (len(nameExcludes) != 0 || len(nameIncludes) != 0) {
		return nil, errors.New(
			"FilterOptions.NameFilter cannot be used at the same time as " +
				"FilterOptions.ExcludeNames or FilterOptions.IncludeNames")
	}

	for _, name := range l.Names() {
		lint := l.byName(name)

		if sourceExcludes != nil && sourceExcludes[lint.Source] {
			continue
		}
		if sourceIncludes != nil && !sourceIncludes[lint.Source] {
			continue
		}
		if opts.NameFilter != nil && !opts.NameFilter.MatchString(name) {
			continue
		}
		if nameExcludes != nil && nameExcludes[name] {
			continue
		}
		if nameIncludes != nil && !nameIncludes[name] {
			continue
		}

		// when adding lints to a filtered linter we do not want Initialize() to
		// be called a second time, so provide false as the initialize argument.
		if err := filteredLinter.register(lint, false); err != nil {
			return nil, err
		}
	}

	return filteredLinter, nil
}

// WriteJSON writes a description of each registered lint as
// a JSON object, one object per line, to the provided writer.
func (l *linterImpl) WriteJSON(w io.Writer) {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, name := range l.Names() {
		_ = enc.Encode(l.byName(name))
	}
}

// TODO(@cpu): Comment this
func (l *linterImpl) Lint(cert *x509.Certificate) *ResultSet {
	rs := newResultSet()

	for _, name := range l.Names() {
		rs.AddResult(name, l.byName(name).Execute(cert))
	}

	rs.LintEndTimestamp = time.Now().Unix()
	return rs
}

// TODO(@cpu): Comment this
func (l *linterImpl) LintByName(lintName string, cert *x509.Certificate) *ResultSet {
	rs := newResultSet()

	if lint := l.byName(lintName); lint != nil {
		rs.AddResult(lintName, lint.Execute(cert))
	}

	rs.LintEndTimestamp = time.Now().Unix()
	return rs
}

// newLinter constructs a linterImpl that can be used to register lints and lint
// certificates.
func newLinter() *linterImpl {
	return &linterImpl{
		lintsByName:   make(map[string]*Lint),
		lintsBySource: make(map[LintSource][]*Lint),
	}
}

var defaultLinter *linterImpl = newLinter()

// RegisterLint must be called once for each lint to be executed. Normally,
// RegisterLint is called from the Go init() function of a lint implementation.
//
// RegsterLint will call l.Lint's Initialize() function as part of the
// registration process.
//
// IMPORTANT: RegisterLint will panic if given a nil lint, or a lint with a nil
// Lint pointer, or if the lint's Initialize function errors, or if the lint
// name matches a previously registered lint's name. These conditions all
// indicate a bug that should be addressed by a developer.
func RegisterLint(l *Lint) {
	// RegisterLint always sets initialize to true. It's assumed this is called by
	// the package init() functions and therefore must be doing the first
	// initialization of a lint.
	if err := defaultLinter.register(l, true); err != nil {
		panic(fmt.Sprintf("RegisterLint error: %v\n", err.Error()))
	}
}

// DefaultLinter is the Linter used by RegisterLint and contains all of the
// lints that ZLint provides.
//
// If you want to run only a subset of the globally registered lints use
// DefaultLinter().Filter with FilterOptions to create a filtered
// Linter.
func DefaultLinter() Linter {
	return defaultLinter
}
