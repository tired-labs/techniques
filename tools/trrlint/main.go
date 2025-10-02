package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/text"
)

type header struct {
	level int
	text  string
}

type rule struct {
	kind     ast.NodeKind
	name     string
	validate func(ast.Node, []byte) (bool, []error)
}

var (
	badCodeRegex *regexp.Regexp = regexp.MustCompile(
		"^\\s*\\>?\\s*```.*```\\s*$",
	)
	badQuoteBlockRegex *regexp.Regexp = regexp.MustCompile(
		`^\s*>[^ ].*`,
	)
	codeRegex *regexp.Regexp = regexp.MustCompile(
		"^\\s*\\>?\\s*```.*$",
	)
	codeWrap    *regexp.Regexp = regexp.MustCompile("^[^`]+`$")
	errorsFound uint
	exts        []string = []string{
		"gif", "jpeg", "jpg", "json", "png",
	}
	flags struct {
		all   bool
		quiet bool
	}
	imgRegex *regexp.Regexp = regexp.MustCompile(
		`^\s*\>?\s*\!\[.+\]\(.+\)\s*$`,
	)
	linted        bool
	listGoodRegex *regexp.Regexp = regexp.MustCompile(
		`^\s*\>?\s*(-|\d+\.)\s\S.+$`,
	)
	listRegex *regexp.Regexp = regexp.MustCompile(
		`^\s*\>?\s*(-[^-]|\d+\.).+$`,
	)
	platformLongs  []string
	platforms      map[string]string
	platformShorts []string
	rules          []rule = []rule{
		{
			kind: ast.KindHeading,
			name: "valid title",
			validate: validateHeader(
				header{1, `/^\S+.*$/`},
				nil,
				0,
			),
		},
		{
			kind: ast.KindHeading,
			name: "level 2 Metadata header",
			validate: validateHeader(
				header{2, "Metadata"},
				nil,
				0,
			),
		},
		{
			kind: ast.KindParagraph,
			name: "mandatory metadata table",
			validate: func(n ast.Node, src []byte) (bool, []error) {
				return matchTable(
					astTxt(n, src),
					[]string{"Key", "Value"},
					[]string{
						"ID",
						"External IDs",
						"Tactics",
						"Platforms",
						"Contributors",
					},
				)
			},
		},
		{
			kind: ast.KindHeading,
			name: "level 2 Technique Overview header",
			validate: validateHeader(
				header{2, "Technique Overview"},
				[]header{{3, "Scope Statement"}},
				0,
			),
		},
		{
			kind: ast.KindHeading,
			name: "level 2 Technical Background header",
			validate: validateHeader(
				header{2, "Technical Background"},
				nil,
				0,
			),
		},
		{
			kind:     ast.KindHeading,
			name:     "level 2 Procedures header",
			validate: validateHeader(header{2, "Procedures"}, nil, 3),
		},
		{
			kind: ast.KindParagraph,
			name: "mandatory procedures table",
			validate: func(n ast.Node, src []byte) (bool, []error) {
				return matchTable(
					astTxt(n, src),
					[]string{"ID", "Title", "Tactic"},
					nil,
				)
			},
		},
		{
			kind: ast.KindHeading,
			name: "level 2 Available Emulation Tests header",
			validate: validateHeader(
				header{2, "Available Emulation Tests"},
				nil,
				3,
			),
		},
		{
			kind: ast.KindParagraph,
			name: "mandatory tests table",
			validate: func(n ast.Node, src []byte) (bool, []error) {
				return matchTable(
					astTxt(n, src),
					[]string{"ID", "Link"},
					nil,
				)
			},
		},
		{
			kind: ast.KindHeading,
			name: "level 2 References header",
			validate: validateHeader(
				header{2, "References"},
				nil,
				0,
			),
		},
		{
			kind: ast.KindList,
			name: "mandatory references list",
			validate: func(_ ast.Node, _ []byte) (bool, []error) {
				return true, nil
			},
		},
		{
			kind: -1,
			name: "EOF",
		},
	}
	tableRegex *regexp.Regexp = regexp.MustCompile(
		`^\s*(\> )?\|.+\|\s*$`,
	)
	trrRegex *regexp.Regexp = regexp.MustCompile(
		`^(docs/examples|reports)/trr\d+/([^/]+)/README.md$`,
	)
	urlGlobalRegex *regexp.Regexp = regexp.MustCompile(
		`^\s*\[.+\]:.+$`,
	)
	urlGoodGlobalRegex *regexp.Regexp = regexp.MustCompile(
		`^\[.+\]:\s.+$|^\[.+\]:\s\[.+\]\(.+\)$`,
	)
	urlInlineRegex *regexp.Regexp = regexp.MustCompile(
		`\[?.+\]\(.+\)|\<https?:\/\/.*\>`,
	)
)

func astTxt(n ast.Node, src []byte) string {
	var segs *text.Segments

	switch n := n.(type) {
	case *ast.Heading:
		segs = n.Lines()
		return string(segs.Value(src))
	case *ast.ListItem:
		switch n := n.FirstChild().(type) {
		case *ast.TextBlock:
			segs = n.Lines()
			return string(segs.Value(src))
		}
	case *ast.Paragraph:
		segs = n.Lines()
		return string(segs.Value(src))
	}

	return "unsupported"
}

func checkAndLint(path string, _ fs.DirEntry, e error) error {
	var directory string
	var entries []fs.DirEntry
	var es []error
	var m []string
	var tmp string

	if e != nil {
		return e
	}

	// OS-agnostic
	path = strings.TrimPrefix(filepath.ToSlash(path), "./")

	// Check if README, but not README.md
	if strings.Contains(path, "README") {
		if !strings.HasSuffix(path, "README.md") {
			e = fmt.Errorf("path %s should end with README.md", path)
			es = append(es, e)
		}
	}

	// Check if all lowercase
	tmp = strings.TrimSuffix(path, "README.md")
	if tmp != strings.ToLower(tmp) {
		e = fmt.Errorf("path %s is not lowercase", path)
		es = append(es, e)
	}

	// Looking for TRRs, so exit if not TRR
	if m = trrRegex.FindStringSubmatch(path); len(m) == 0 {
		displayErrors(es)
		return nil
	}

	linted = true

	// Ensure there are no images or json in the same directory
	entries, _ = os.ReadDir(filepath.Dir(path))
	for _, entry := range entries {
		for _, ext := range exts {
			if strings.HasSuffix(entry.Name(), "."+ext) {
				es = append(
					es,
					fmt.Errorf(
						"%s should be in appropriate sub-directory",
						entry.Name(),
					),
				)
			}
		}
	}

	// Validate directory matches short platform ID
	directory = filepath.Base(filepath.Dir(path))
	if e = validateDirectory(directory); e != nil {
		es = append(es, e)
	}

	// Lint TRR
	es = append(es, lintFile(path)...)

	displayErrors(es)
	return nil
}

func checkRule(idx int, n ast.Node, src []byte) (int, []error) {
	var es []error
	var matched bool
	var tmp []error

	switch rules[idx].kind {
	case -1, ast.KindHeading:
	default:
		switch n := n.(type) {
		case *ast.Heading:
			if n.Level <= 2 {
				for i := idx; i < len(rules); i++ {
					if (rules[i].kind == ast.KindHeading) ||
						(rules[i].kind == -1) {
						idx = i
						break
					}

					es = append(
						es,
						fmt.Errorf(
							"expected %s, got none",
							rules[i].name,
						),
					)
				}
			}
		}
	}

	switch rules[idx].kind {
	case -1: // End of rules
		switch n := n.(type) {
		case *ast.Heading:
			if n.Level <= 2 {
				es = append(
					es,
					fmt.Errorf(
						"expected no more headers, got %s",
						astTxt(n, src),
					),
				)
			}
		}
	}

	if n.Kind() != rules[idx].kind {
		return idx, es
	}

	if matched, tmp = rules[idx].validate(n, src); matched {
		idx++
	}

	return idx, append(es, tmp...)
}

func compareTable(want, got []string, it string) []error {
	var es []error
	var keep []string

	if want == nil {
		return nil
	}

	for i := range got {
		if slices.Contains(want, got[i]) {
			keep = append(keep, got[i])
		} else {
			es = append(
				es,
				fmt.Errorf("table contains extra %s: %s", it, got[i]),
			)
		}
	}

	got = keep
	keep = []string{}

	for i := range want {
		if slices.Contains(got, want[i]) {
			keep = append(keep, want[i])
		} else {
			es = append(
				es,
				fmt.Errorf("table is missing %s: %s", it, want[i]),
			)
		}
	}

	want = keep

	for i := range want {
		if want[i] != got[i] {
			es = append(
				es,
				fmt.Errorf(
					"table %s expected %s, got %s",
					it,
					want[i],
					got[i],
				),
			)
		}
	}

	return es
}

func displayErrors(es []error) {
	errorsFound += uint(len(es))
	if !flags.quiet {
		for _, e := range es {
			fmt.Printf("[!] %s\n", e)
		}
	}
}

func exit(e error) {
	if e != nil {
		fmt.Printf("[!] %s\n", e)
	}

	os.Exit(1)
}

func init() {
	flag.BoolVar(&flags.quiet, "q", false, "Suppress output.")
	flag.Parse()
}

func indent(s string) string {
	var ss []string = strings.Split(s, "\n")

	for i := range ss {
		ss[i] = "\t" + ss[i]
	}

	return strings.Join(ss, "\n")
}

func lintFile(fn string) []error {
	var b []byte
	var e error
	var es []error
	var idx int

	if !flags.quiet {
		fmt.Printf("[*] Linting %s\n", fn)
	}

	if b, e = os.ReadFile(fn); e != nil {
		return []error{e}
	}

	e = ast.Walk(
		goldmark.DefaultParser().Parse(text.NewReader(b)),
		func(n ast.Node, entering bool) (ast.WalkStatus, error) {
			var errs []error

			if entering {
				switch n.(type) {
				case *ast.Heading:
				case *ast.List:
				case *ast.Paragraph:
				default:
					return ast.WalkContinue, nil
				}

				if idx, errs = checkRule(idx, n, b); len(errs) > 0 {
					es = append(es, errs...)
				}
			}

			return ast.WalkContinue, nil
		},
	)
	if e != nil {
		es = append(es, e)
	}

	if idx != len(rules)-1 {
		e = fmt.Errorf("expected %s, got none", rules[idx].name)
		es = append(es, e)
	}

	return append(es, postProcessing(string(b), 80)...)
}

func main() {
	var b []byte
	var e error
	var roots []string = []string{"docs/examples", "reports"}

	// Read in supported platforms
	if b, e = os.ReadFile("platforms.json"); e != nil {
		exit(e)
	}

	if e = json.Unmarshal(b, &platforms); e != nil {
		exit(e)
	}

	for long, short := range platforms {
		platformLongs = append(platformLongs, long)
		platformShorts = append(platformShorts, short)
	}

	if flag.NArg() == 0 {
		// Find all completed TRRs
		for _, root := range roots {
			if e = filepath.WalkDir(root, checkAndLint); e != nil {
				exit(e)
			}
		}
	}

	for _, arg := range flag.Args() {
		if e = checkAndLint(arg, nil, nil); e != nil {
			exit(e)
		}
	}

	if !flags.quiet {
		if !linted {
			fmt.Printf("[!] No lintable files found\n")
		} else if errorsFound == 0 {
			fmt.Printf("[+] Finished: 0 total errors found\n")
		} else if errorsFound == 1 {
			fmt.Printf("[-] Finished: 1 total error found\n")
		} else {
			fmt.Printf(
				"[-] Finished: %d total errors found\n",
				errorsFound,
			)
		}
	}

	if errorsFound > 255 {
		os.Exit(255)
	}

	if !linted {
		errorsFound++
	}

	os.Exit(int(errorsFound))
}

func matchHeader(n *ast.Heading, txt string, match header) error {
	var r *regexp.Regexp

	if n.Level != match.level {
		return fmt.Errorf(
			"expected header level %d, got %d for %s",
			match.level,
			n.Level,
			txt,
		)
	}

	if strings.HasPrefix(match.text, "/") {
		r = regexp.MustCompile(match.text[1 : len(match.text)-1])

		if !r.MatchString(txt) {
			return fmt.Errorf(
				"expected header matching %s, got %s",
				match.text,
				txt,
			)
		}
	} else if txt != match.text {
		return fmt.Errorf(
			"expected header %s, got %s",
			match.text,
			txt,
		)
	}

	return nil
}

func matchTable(txt string, cols, rows []string) (bool, []error) {
	var e error
	var es []error
	var got []string
	var lines []string = strings.Split(txt, "\n")
	var numCols int
	var tmp []string

	// Validate table format first
	for i, line := range lines {
		if (i < 2) && !tableRegex.MatchString(line) {
			return false, nil
		}

		// Validate columns
		if i == 0 {
			line = strings.TrimSpace(line)
			tmp = strings.Split(strings.Trim(line, "|"), "|")
			for i := range tmp {
				tmp[i] = strings.TrimSpace(tmp[i])
			}

			es = append(es, compareTable(cols, tmp, "header")...)
		}

		if i >= 2 {
			break
		}
	}

	// Validate consistent number of columns
	for i, line := range lines {
		line = strings.TrimSpace(line)
		tmp = strings.Split(strings.Trim(line, "|"), "|")
		for i := range tmp {
			tmp[i] = strings.TrimSpace(tmp[i])
		}

		if numCols == 0 {
			numCols = len(tmp)
		} else if len(tmp) != numCols {
			e = fmt.Errorf(
				"expected consistent table columns, got:\n%s",
				indent(txt),
			)
			es = append(es, e)
		}

		if (i >= 2) && (len(tmp) > 0) {
			got = append(got, tmp[0])
		}
	}

	es = append(es, compareTable(rows, got, "row")...)

	return true, es
}

func postProcessing(s string, w int) []error {
	var code bool
	var e error
	var es []error
	var footnotes bool

	for i, line := range strings.Split(s, "\n") {
		line = strings.TrimSuffix(line, "\r")

		if codeRegex.MatchString(line) {
			if !badCodeRegex.MatchString(line) {
				code = !code
			} else {
				e = fmt.Errorf(
					"line %d has non-standard inline code block",
					i+1,
				)
				es = append(es, e)
			}
		}

		if code || imgRegex.MatchString(line) {
			continue
		} else if urlGlobalRegex.MatchString(line) {
			footnotes = true

			// Report on bad global urls
			if !urlGoodGlobalRegex.MatchString(line) {
				e = fmt.Errorf(
					"line %d expected [text]: link, got:\n%s",
					i+1,
					indent(line),
				)
				es = append(es, e)
			}

			continue
		}

		// Report on bad quote-blocks
		if badQuoteBlockRegex.MatchString(line) {
			e = fmt.Errorf(
				"lines %d: quote-block must have exactly one space after '>'",
				i+1,
			)
			es = append(es, e)
		}

		// Report on bad list items
		if !tableRegex.MatchString(line) {
			if listRegex.MatchString(line) {
				if !codeWrap.MatchString(line) {
					if !listGoodRegex.MatchString(line) {
						e = fmt.Errorf(""+
							"line %d is an improperly formatted list"+
							" item",
							i+1,
						)
						es = append(es, e)
					}
				}
			}
		}

		if !footnotes {
			// Report on inline URL use
			if urlInlineRegex.MatchString(line) {
				e = fmt.Errorf("line %d is using inline url", i+1)
				es = append(es, e)
			}
		}

		if !footnotes && !tableRegex.MatchString(line) {
			// Check line length
			if utf8.RuneCountInString(line) > w {
				e = fmt.Errorf(
					"line %d is over char limit (%d)",
					i+1,
					w,
				)
				es = append(es, e)
			}
		}
	}

	if code {
		e = fmt.Errorf("expected code block end, got none")
		es = append(es, e)
	}

	return es
}

func validateDirectory(directory string) error {
	// loop through shorties, if it matches, return nil, if you get to end return err
	for _, short := range platformShorts {
		if directory == short {
			return nil
		}
	}

	return fmt.Errorf("%s is not a valid platform", directory)
}

func validateHeader(
	h header, optionals []header, skipLvls int,
) func(ast.Node, []byte) (bool, []error) {
	return func(n ast.Node, src []byte) (bool, []error) {
		var txt string = astTxt(n, src)

		switch n := n.(type) {
		case *ast.Heading:
			for _, optional := range optionals {
				if e := matchHeader(n, txt, optional); e == nil {
					return false, nil
				}
			}

			if (skipLvls > 0) && (n.Level >= skipLvls) {
				return false, nil
			}

			if e := matchHeader(n, txt, h); e != nil {
				return true, []error{e}
			}

			return true, nil
		}

		return false, []error{
			fmt.Errorf(
				"expected Header, got %s",
				n.Kind().String(),
			),
		}
	}
}
