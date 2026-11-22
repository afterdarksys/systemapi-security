package paths

import "testing"

func TestUnder(t *testing.T) {
	if !Under("/var/lib/secsvc", "/var/lib") {
		t.Fatal("descendant")
	}
	if Under("/var/lib2", "/var/lib") {
		t.Fatal("prefix collision")
	}
	if Under("/var/lib", "/") || Under("/", "/var") {
		t.Fatal("root covers nothing")
	}
	if !IsRoot("/") || !IsRoot("//") || !IsRoot("/./") || !IsRoot("/..") || !IsRoot("/tmp/../..") {
		t.Fatal("root forms")
	}
	if IsRoot("/tmp/../tmp") || IsAbsClean("/tmp/../tmp") || IsAbsClean("tmp") || IsAbsClean("/tmp/") {
		t.Fatal("unclean")
	}
	if !IsAbsClean("/tmp/a") {
		t.Fatal("clean abs")
	}
}
