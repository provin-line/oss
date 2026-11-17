package auditor_test

import (
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"testing"
)

// wireviewRoots are the service roots that hand their wirecontract's
// functions on under their own names. Each is a func, not a variable that
// holds one: a variable could be assigned, and its address taken. A root that
// comes to hand on its wirecontract's functions belongs here.
var wireviewRoots = []string{".", "../tlogservice", "../chainmanager", "../payloadresolver"}

// No exported package-level variable of these packages holds a function.
func TestServiceRoots_ExportNoFuncValuedVars(t *testing.T) {
	for _, dir := range wireviewRoots {
		fset := token.NewFileSet()
		bp, err := build.Default.ImportDir(dir, 0)
		if err != nil {
			t.Fatal(err)
		}
		var files []*ast.File
		for _, name := range bp.GoFiles {
			f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			files = append(files, f)
		}
		conf := types.Config{Importer: importer.ForCompiler(fset, "source", nil)}
		pkg, err := conf.Check(dir, fset, files, nil)
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		for _, name := range pkg.Scope().Names() {
			v, ok := pkg.Scope().Lookup(name).(*types.Var)
			if !ok || !v.Exported() {
				continue
			}
			if _, isFunc := v.Type().Underlying().(*types.Signature); isFunc {
				t.Errorf("%s: %s is a variable holding a function; make it a func", pkg.Name(), name)
			}
		}
	}
}
