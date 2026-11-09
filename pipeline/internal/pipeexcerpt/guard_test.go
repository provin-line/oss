package pipeexcerpt_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// logMethods are the slog calls whose arguments after the message are
// key-value pairs.
var logMethods = map[string]bool{
	"Debug": true, "Info": true, "Warn": true, "Error": true,
	"DebugContext": true, "InfoContext": true, "WarnContext": true, "ErrorContext": true,
}

// boundedKeys are the log attribute keys whose value is an error's text.
var boundedKeys = map[string]bool{"err": true, "error": true}

// Every log attribute of the pipeline's code that names an error ("err" or
// "error") takes its value through pipeexcerpt (ErrorText, or Text for a
// text that is an error's), as a key-value pair after the message or as an
// slog.String or slog.Any: a log line of the pipeline names no error unbounded.
func TestEveryLoggedErrorIsBounded(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	checked := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
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
			switch {
			case logMethods[sel.Sel.Name]:
				for i := 0; i+1 < len(call.Args); i++ {
					if boundedKeys[stringLit(call.Args[i])] {
						checked++
						if !throughPipeexcerpt(call.Args[i+1]) {
							t.Errorf("%s: log attribute %s is not bounded by pipeexcerpt", fset.Position(call.Args[i+1].Pos()), stringLit(call.Args[i]))
						}
						i++
					}
				}
			case isPackage(sel, "slog") && (sel.Sel.Name == "String" || sel.Sel.Name == "Any") && len(call.Args) == 2 && boundedKeys[stringLit(call.Args[0])]:
				checked++
				if !throughPipeexcerpt(call.Args[1]) {
					t.Errorf("%s: slog.%s(%s) is not bounded by pipeexcerpt", fset.Position(call.Args[1].Pos()), sel.Sel.Name, stringLit(call.Args[0]))
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 20 {
		t.Fatalf("checked %d logged errors: the walk found too few for the pipeline's code", checked)
	}
}

func stringLit(e ast.Expr) string {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return ""
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return ""
	}
	return s
}

func isPackage(sel *ast.SelectorExpr, name string) bool {
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == name
}

func throughPipeexcerpt(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && isPackage(sel, "pipeexcerpt") && (sel.Sel.Name == "ErrorText" || sel.Sel.Name == "Text")
}
