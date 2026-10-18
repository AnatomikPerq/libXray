// Command protogen writes ../config.pb.go from ../config.proto without protoc:
// protocompile parses the file and protoc-gen-go, run as a plugin, prints Go.
package main

import (
	"bytes"
	"context"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/bufbuild/protocompile"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/pluginpb"
)

func main() {
	const source = "amneziawg/config.proto"
	compiler := protocompile.Compiler{
		Resolver: protocompile.WithStandardImports(&protocompile.SourceResolver{ImportPaths: []string{"../.."}}),
	}
	files, err := compiler.Compile(context.Background(), source)
	if err != nil {
		log.Fatal(err)
	}
	request := &pluginpb.CodeGeneratorRequest{
		FileToGenerate: []string{source},
		Parameter:      proto.String("paths=source_relative"),
		ProtoFile:      []*descriptorpb.FileDescriptorProto{protodesc.ToFileDescriptorProto(files[0])},
	}
	input, err := proto.Marshal(request)
	if err != nil {
		log.Fatal(err)
	}
	plugin := exec.Command("go", "run", "google.golang.org/protobuf/cmd/protoc-gen-go")
	plugin.Stdin = bytes.NewReader(input)
	plugin.Stderr = os.Stderr
	output, err := plugin.Output()
	if err != nil {
		log.Fatal(err)
	}
	var response pluginpb.CodeGeneratorResponse
	if err := proto.Unmarshal(output, &response); err != nil {
		log.Fatal(err)
	}
	if response.Error != nil {
		log.Fatal(response.GetError())
	}
	for _, file := range response.File {
		if err := os.WriteFile(filepath.Join("../..", file.GetName()), []byte(file.GetContent()), 0o644); err != nil {
			log.Fatal(err)
		}
	}
}
