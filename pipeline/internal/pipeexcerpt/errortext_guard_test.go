package pipeexcerpt_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var (
	// fmtFormats are fmt's functions that take a format, each with the index
	// of the format among its arguments.
	fmtFormats = map[string]int{"Sprintf": 0, "Errorf": 0, "Printf": 0, "Fprintf": 1, "Appendf": 1}
	// fmtPrints are fmt's functions that write their arguments as %v does.
	fmtPrints = map[string]bool{"Sprint": true, "Sprintln": true, "Print": true, "Println": true, "Fprint": true, "Fprintln": true, "Append": true, "Appendln": true}
	// errorName is how this module names a variable or a field that holds an
	// error.
	errorName = regexp.MustCompile(`^([a-z]*err\d*|\w+Err\d*)$`)
)

// The pipeline's code builds a text from an error only through excerpt
// (excerpt.ErrorText, or pipeexcerpt's forms of it), which does not let a
// panic of the error's methods leave: outside pipeexcerpt, no fmt verb other
// than %w (and %T, %p) writes an error value, and no Error method is called
// directly.
//
// Wrapping with %w stays as it is. fmt recovers an ordinary panic of an
// error's Error or Format method and writes it; what it does not recover is
// a panic whose value it cannot write either, or a method that does not
// return. The parts plugged into the pipeline promise that their errors do
// neither (package contract); a part that breaks that can make a %w wrap
// panic or not return.
//
// It reads the code as written, not its types: an error is a variable or a
// field named as this module names one, or an Error() call; %T and %p, which
// call no method, are allowed. fmt imported under another name is read. It
// does not see an error under another name, one that is an expression (a
// call such as ctx.Err(), an index, a conversion), one inside a value fmt
// writes, an Error method taken as a value, or a verb with an explicit
// argument index (%[1]v), which it maps by position.
func TestNoTextIsBuiltFromAnErrorOutsideExcerpt(t *testing.T) {
	root := filepath.Join("..", "..")
	own, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	checked := 0
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if abs, _ := filepath.Abs(p); abs == own {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			return err
		}
		fmtNames := map[string]bool{}
		for _, s := range f.Imports {
			if ip, _ := strconv.Unquote(s.Path.Value); ip == "fmt" {
				name := path.Base(ip)
				if s.Name != nil {
					name = s.Name.Name
				}
				fmtNames[name] = true
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			where := fset.Position(call.Pos())
			if sel.Sel.Name == "Error" && len(call.Args) == 0 {
				t.Errorf("%s: an Error() call builds a text from an error outside excerpt", where)
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok || !fmtNames[id.Name] {
				return true
			}
			if i, ok := fmtFormats[sel.Sel.Name]; ok && i < len(call.Args) {
				checked++
				for _, a := range errorsNotWrapped(call.Args[i], call.Args[i+1:]) {
					t.Errorf("%s: fmt.%s writes the error %s with a verb other than %%w", where, sel.Sel.Name, a)
				}
				return true
			}
			if fmtPrints[sel.Sel.Name] {
				checked++
				for _, a := range call.Args {
					if name := errorValue(a); name != "" {
						t.Errorf("%s: fmt.%s writes the error %s", where, sel.Sel.Name, name)
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 100 {
		t.Fatalf("checked %d fmt calls: the walk found too few for the pipeline's code", checked)
	}
}

// errorsNotWrapped names the error values among args that format writes with
// a verb other than %w. A format that is not a literal is taken to write every
// argument so.
func errorsNotWrapped(format ast.Expr, args []ast.Expr) []string {
	verbs, literal := formatVerbs(format)
	var named []string
	for i, a := range args {
		name := errorValue(a)
		if name == "" {
			continue
		}
		if literal && i < len(verbs) && (verbs[i] == 'w' || verbs[i] == 'T' || verbs[i] == 'p') {
			continue
		}
		named = append(named, name)
	}
	return named
}

// formatVerbs are the verbs of a literal format, one per argument it takes,
// in order; false when format is not a literal.
func formatVerbs(format ast.Expr) ([]rune, bool) {
	lit, ok := format.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return nil, false
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return nil, false
	}
	var verbs []rune
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			continue
		}
		i++
		for i < len(s) && strings.ContainsRune("+-# 0123456789.*[]", rune(s[i])) {
			if s[i] == '*' {
				verbs = append(verbs, '*')
			}
			i++
		}
		if i < len(s) && s[i] != '%' {
			verbs = append(verbs, rune(s[i]))
		}
	}
	return verbs, true
}

// errorValue is the name of e when it is an error value as this module names
// one, or "".
func errorValue(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.Ident:
		if errorName.MatchString(e.Name) {
			return e.Name
		}
	case *ast.SelectorExpr:
		if errorName.MatchString(e.Sel.Name) {
			return e.Sel.Name
		}
	}
	return ""
}
