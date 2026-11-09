package netexcerpt_test

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

const (
	module         = "github.com/provin-line/oss"
	netexcerptPath = module + "/internal/netexcerpt"
	excerptPath    = module + "/internal/excerpt"
)

// guardedDirs are the directories, from this package's, of the network's
// code that runs while the node serves: its services, the server that
// composes them, and the HTTP server. cmd/network is not among them: its log
// lines are of its start and its shutdown, whose errors come from its
// configuration, its own stores, the building of the server and Serve, not
// from what others send. A log line it gains while it handles requests (a way
// others' text may come) puts it among them.
var guardedDirs = []string{"../../network", "../netcompose", "../httpserve"}

// importerDirs hold code that imports the guarded code without being guarded.
var importerDirs = []string{"../../cmd/network"}

var (
	// slogMethods are slog's calls that write a log line or attributes for
	// one, each with the index of its first key-value argument.
	slogMethods = map[string]int{
		"Debug": 1, "Info": 1, "Warn": 1, "Error": 1,
		"DebugContext": 2, "InfoContext": 2, "WarnContext": 2, "ErrorContext": 2,
		"Log": 3, "LogAttrs": 3, "With": 0,
	}
	// logMethods are the log package's: what follows is a format's
	// arguments, or printed as it is.
	logMethods = map[string]bool{
		"Print": true, "Printf": true, "Println": true,
		"Fatal": true, "Fatalf": true, "Fatalln": true,
		"Panic": true, "Panicf": true, "Panicln": true,
	}
	// errorKeys are the slog keys whose value is an error's text.
	errorKeys = map[string]bool{"err": true, "error": true}
	// errorName is how this module names a variable that holds an error.
	errorName = regexp.MustCompile(`^([a-z]*err\d*|\w+Err\d*)$`)
	// majorVersion is the last element of a module path's major version.
	majorVersion = regexp.MustCompile(`^v[0-9]+$`)
)

// Every log line of the network's code writes an error only through
// netexcerpt:
//   - a slog attribute "err" or "error", as a key-value pair or as
//     slog.String or slog.Any, is netexcerpt.ErrorText of it;
//   - no argument of a slog or log call names an error (a variable named as
//     this module names one, or an Error() call) outside a call into
//     netexcerpt;
//   - no argument calls package excerpt itself, whose ErrorText is whole and
//     whose cuts are not the network's.
//
// It reads the code as written, not its types: a value named in a log line
// (a hash, a DID, an endpoint) looks like any other expression, and is for
// review to see written with netexcerpt.ValueText. A file that imports
// testing is test support, not code that runs while the node serves; no code
// that runs may import its package.
func TestEveryLoggedErrorIsBounded(t *testing.T) {
	fset := token.NewFileSet()
	checked := 0
	support := map[string]string{}  // test support's import path → a file of it
	imported := map[string]string{} // what running code imports → a file importing it
	walk := func(dir string, guarded bool) {
		err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(fset, p, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			imports := importNames(f)
			for _, ip := range imports {
				if ip == "testing" {
					support[packagePath(p)] = p
					return nil
				}
			}
			for _, ip := range imports {
				imported[ip] = p
			}
			if guarded {
				f, err := parser.ParseFile(fset, p, nil, 0)
				if err != nil {
					return err
				}
				checked += checkFile(t, fset, f, imports)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range guardedDirs {
		walk(dir, true)
	}
	for _, dir := range importerDirs {
		walk(dir, false)
	}
	for ip, file := range support {
		if by, ok := imported[ip]; ok {
			t.Errorf("%s imports %s, test support (%s imports testing)", by, ip, file)
		}
	}
	t.Logf("checked %d log calls", checked)
	if checked < 25 {
		t.Fatalf("checked %d log calls: the walk found too few for the network's code", checked)
	}
}

// checkFile reports the log calls of f that write an error otherwise than
// through netexcerpt, and returns how many it read.
func checkFile(t *testing.T, fset *token.FileSet, f *ast.File, imports map[string]string) int {
	t.Helper()
	pkgs := packagesOf(imports)
	checked := 0
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		where := fset.Position(call.Pos())
		pkg := ""
		if id, ok := sel.X.(*ast.Ident); ok {
			pkg = imports[id.Name]
		}
		if pkg == "log/slog" && (sel.Sel.Name == "String" || sel.Sel.Name == "Any") && len(call.Args) == 2 {
			if key, ok := stringLit(call.Args[0]); ok && errorKeys[key] {
				checked++
				if !pkgs.call(call.Args[1], netexcerptPath, "ErrorText") {
					t.Errorf("%s: slog.%s(%q) is not netexcerpt.ErrorText", where, sel.Sel.Name, key)
				}
			}
			return true
		}
		first, isSlog := slogMethods[sel.Sel.Name]
		isLog := logMethods[sel.Sel.Name]
		if !isSlog && !isLog {
			return true
		}
		if pkg != "" && !(isSlog && pkg == "log/slog") && !(isLog && pkg == "log") {
			return true // another package's function, such as http.Error
		}
		checked++
		for _, a := range call.Args {
			if what := pkgs.unbounded(a); what != "" {
				t.Errorf("%s: %s is not written through netexcerpt", where, what)
			}
		}
		if isSlog {
			for i := first; i < len(call.Args); {
				key, ok := stringLit(call.Args[i])
				if !ok {
					i++ // an slog.Attr
					continue
				}
				if errorKeys[key] && i+1 < len(call.Args) && !pkgs.call(call.Args[i+1], netexcerptPath, "ErrorText") {
					t.Errorf("%s: attribute %q is not netexcerpt.ErrorText", where, key)
				}
				i += 2
			}
		}
		return true
	})
	return checked
}

// importNames maps the name each import of f is known by to its path.
func importNames(f *ast.File) map[string]string {
	names := map[string]string{}
	for _, s := range f.Imports {
		ip, err := strconv.Unquote(s.Path.Value)
		if err != nil {
			continue
		}
		name := path.Base(ip)
		if majorVersion.MatchString(name) && path.Dir(ip) != "." {
			name = path.Base(path.Dir(ip))
		}
		if s.Name != nil {
			name = s.Name.Name
		}
		names[name] = ip
	}
	return names
}

// packagePath is the import path of the package of the file at p, a path
// from this package's directory.
func packagePath(p string) string {
	rel, err := filepath.Rel(filepath.Join("..", ".."), filepath.Dir(p))
	if err != nil {
		return ""
	}
	return module + "/" + filepath.ToSlash(rel)
}

// fileImports are the names a file knows packages by, keyed by path.
type fileImports map[string]map[string]bool

func packagesOf(imports map[string]string) fileImports {
	pkgs := fileImports{}
	for name, ip := range imports {
		if pkgs[ip] == nil {
			pkgs[ip] = map[string]bool{}
		}
		pkgs[ip][name] = true
	}
	return pkgs
}

// call reports whether e is a call of the function name of the package at ip.
func (pkgs fileImports) call(e ast.Expr, ip, name string) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && pkgs[ip][id.Name] && sel.Sel.Name == name
}

// unbounded names the first part of e that writes an error, or calls package
// excerpt, outside a call into netexcerpt; "" when there is none.
func (pkgs fileImports) unbounded(e ast.Expr) string {
	what := ""
	ast.Inspect(e, func(n ast.Node) bool {
		if what != "" {
			return false
		}
		switch n := n.(type) {
		case *ast.CallExpr:
			sel, ok := n.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok {
				switch {
				case pkgs[netexcerptPath][id.Name]:
					return false
				case pkgs[excerptPath][id.Name]:
					what = "a call of excerpt." + sel.Sel.Name
					return false
				}
			}
			if sel.Sel.Name == "Error" && len(n.Args) == 0 {
				what = "an Error() call"
				return false
			}
		case *ast.Ident:
			if errorName.MatchString(n.Name) {
				what = "the error " + n.Name
			}
		}
		return true
	})
	return what
}

// stringLit is the value of e when it is a string literal.
func stringLit(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return s, true
}
