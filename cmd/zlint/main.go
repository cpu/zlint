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

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/lint"
)

var ( // flags
	listLintsJSON   bool
	listLintsSchema bool
	listLintSources bool
	prettyprint     bool
	format          string
	nameFilter      string
	includeNames    string
	excludeNames    string
	includeSources  string
	excludeSources  string
	minStatusLabel  string

	// version is replaced by GoReleaser using an LDFlags option at release time.
	version = "dev"
)

func init() {
	flag.BoolVar(&listLintsJSON, "list-lints-json", false, "Print lints in JSON format, one per line")
	flag.BoolVar(&listLintsSchema, "list-lints-schema", false, "Print lints as a ZSchema")
	flag.BoolVar(&listLintSources, "list-lints-source", false, "Print list of lint sources, one per line")
	flag.StringVar(&format, "format", "pem", "One of {pem, der, base64}")
	flag.StringVar(&nameFilter, "nameFilter", "", "Only run lints with a name matching the provided regex. (Can not be used with -includeNames/-excludeNames)")
	flag.StringVar(&includeNames, "includeNames", "", "Comma-separated list of lints to include by name")
	flag.StringVar(&excludeNames, "excludeNames", "", "Comma-separated list of lints to exclude by name")
	flag.StringVar(&includeSources, "includeSources", "", "Comma-separated list of lint sources to include")
	flag.StringVar(&excludeSources, "excludeSources", "", "Comma-separated list of lint sources to exclude")
	flag.StringVar(&minStatusLabel, "minStatus", "", `Only output lint results > provided status level (e.g. "warn", "error")`)

	flag.BoolVar(&prettyprint, "pretty", false, "Pretty-print output")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "ZLint version %s\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] file...\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	log.SetLevel(log.InfoLevel)
}

func main() {
	// Build a linter of lints to run using the include/exclude lint name and
	// source flags.
	linter, err := setLints()
	if err != nil {
		log.Fatalf("unable to configure included/exclude lints: %v\n", err)
	}

	if listLintsJSON {
		linter.WriteJSON(os.Stdout)
		return
	}

	if listLintsSchema {
		names := linter.Names()
		fmt.Printf("Lints = SubRecord({\n")
		for _, lintName := range names {
			fmt.Printf("    %q:LintBool(),\n", lintName)
		}
		fmt.Printf("})\n")
		return
	}

	if listLintSources {
		sources := linter.Sources()
		sort.Sort(sources)
		for _, source := range sources {
			fmt.Printf("    %s\n", source)
		}
		return
	}

	var minStatus *lint.LintStatus
	if minStatusLabel != "" {
		minStatus = new(lint.LintStatus)
		minStatus.FromString(minStatusLabel)
	}

	var inform = strings.ToLower(format)
	if flag.NArg() < 1 || flag.Arg(0) == "-" {
		doLint(os.Stdin, inform, linter, minStatus)
	} else {
		for _, filePath := range flag.Args() {
			var inputFile *os.File
			var err error
			inputFile, err = os.Open(filePath)
			if err != nil {
				log.Fatalf("unable to open file %s: %s", filePath, err)
			}
			var fileInform = inform
			switch {
			case strings.HasSuffix(filePath, ".der"):
				fileInform = "der"
			case strings.HasSuffix(filePath, ".pem"):
				fileInform = "pem"
			}

			doLint(inputFile, fileInform, linter, minStatus)
			inputFile.Close()
		}
	}
}

func doLint(inputFile *os.File, inform string, linter lint.Linter, minStatus *lint.LintStatus) {
	fileBytes, err := ioutil.ReadAll(inputFile)
	if err != nil {
		log.Fatalf("unable to read file %s: %s", inputFile.Name(), err)
	}

	var asn1Data []byte
	switch inform {
	case "pem":
		p, _ := pem.Decode(fileBytes)
		if p == nil || p.Type != "CERTIFICATE" {
			log.Fatal("unable to parse PEM")
		}
		asn1Data = p.Bytes
	case "der":
		asn1Data = fileBytes
	case "base64":
		asn1Data, err = base64.StdEncoding.DecodeString(string(fileBytes))
		if err != nil {
			log.Fatalf("unable to parse base64: %s", err)
		}
	default:
		log.Fatalf("unknown input format %s", format)
	}

	c, err := x509.ParseCertificate(asn1Data)
	if err != nil {
		log.Fatalf("unable to parse certificate: %s", err)
	}

	zlintResult := linter.Lint(c)
	jsonBytes, err := json.Marshal(zlintResult.Results)
	if err != nil {
		log.Fatalf("unable to encode lints JSON: %s", err)
	}

	// If requested, filter the results to just those above a specific status
	// level.
	if minStatus != nil {
		zlintResult.Results = zlintResult.Above(*minStatus)
	}

	if prettyprint {
		var out bytes.Buffer
		if err := json.Indent(&out, jsonBytes, "", " "); err != nil {
			log.Fatalf("can't format output: %s", err)
		}
		os.Stdout.Write(out.Bytes())
	} else {
		os.Stdout.Write(jsonBytes)
	}
	os.Stdout.Write([]byte{'\n'})
	os.Stdout.Sync()
}

// trimmedList takes a comma separated string argument in raw, splits it by
// comma, and returns a list of the separated elements after trimming spaces
// from each element.
func trimmedList(raw string) []string {
	var list []string
	for _, item := range strings.Split(raw, ",") {
		list = append(list, strings.TrimSpace(item))
	}
	return list
}

// setLints returns a filtered linter to use based on the nameFilter,
// includeNames, excludeNames, includeSources, and excludeSources flag values in
// use.
func setLints() (lint.Linter, error) {
	// If there's no filter options set, use the global linter as-is
	if nameFilter == "" && includeNames == "" && excludeNames == "" && includeSources == "" && excludeSources == "" {
		return lint.DefaultLinter(), nil
	}

	filterOpts := lint.FilterOptions{}
	if nameFilter != "" {
		r, err := regexp.Compile(nameFilter)
		if err != nil {
			return nil, fmt.Errorf("bad -nameFilter: %v", err)
		}
		filterOpts.NameFilter = r
	}
	if excludeSources != "" {
		if err := filterOpts.ExcludeSources.FromString(excludeSources); err != nil {
			log.Fatalf("invalid -excludeSources: %v", err)
		}
	}
	if includeSources != "" {
		if err := filterOpts.IncludeSources.FromString(includeSources); err != nil {
			log.Fatalf("invalid -includeSources: %v\n", err)
		}
	}
	if excludeNames != "" {
		filterOpts.ExcludeNames = trimmedList(excludeNames)
	}
	if includeNames != "" {
		filterOpts.IncludeNames = trimmedList(includeNames)
	}

	return lint.DefaultLinter().Filter(filterOpts)
}
