// Command provin is the operator CLI for DID, schema, and chain management
// against a dplaax registry (see README.md). Stage 1 implements the owner /
// pipeline / process groups — the wire-only bootstrap a deployed node needs
// before its loops can sign.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/provin-line/oss/cmd/provin/internal/commands"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "provin:", err)
		os.Exit(1)
	}
}

const usage = `usage: provin <group> <operation> [flags]

Implemented:
  owner    init       --did <owner-did> --key <jwk-path>     register a pipeline owner
  pipeline create     --did <target-did> --owner-key <path>  issue a pipeline DID
  process  create     --did <target-did> --owner-key <path>  issue a process DID
  bundle   export     --head <sha256:hex> --out <dir>        archive a chain + its authority documents
                      [--aggregate-complete] [--did-base <registry>=<url>]... [--vc-resolver-base <registry>=<url>]...
                      [--allow-loopback] [--allow-private] [--max-depth <n>]
  bundle   verify     --bundle <dir> --head <sha256:hex> and/or --digest <sha256:hex>
                                                              re-verify a bundle offline (no network)
  schema   register   --name <name> --format <format> --file <path|-> [--prerelease <label>]
                                                              register an immutable schema version (- reads the body from stdin)
  chain    subscribe  --subscriber <did> --publisher <did> [--delivery inline|by-reference]
                                                              subscribe to a publisher (delivery mode is REQUESTED, never server-confirmed)
  chain    set-allow  --pipeline <did> --pattern <glob> [--pattern <glob>...] | --clear
                                                              REPLACE the pipeline's entire allow-list (full replacement; --clear for deny-all)

Global flags (owner/pipeline/process/bundle export/schema register/chain subscribe/chain set-allow):
  --registry <base-url>   registry base URL   (env PROVIN_REGISTRY)
  --token    <token>      L1 bearer token     (env PROVIN_TOKEN)

Planned (see README.md): org verify.`

// run dispatches one CLI invocation. It is the testable seam: main wires
// os.Args/os.Stdin/os.Stdout and maps an error to exit code 1.
func run(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) < 2 {
		return fmt.Errorf("missing command\n%s", usage)
	}
	group, op, rest := args[0], args[1], args[2:]
	switch group + " " + op {
	case "owner init":
		return ownerInit(ctx, rest, stdout)
	case "pipeline create":
		return issueCmd(ctx, rest, stdout, commands.PipelineCreate)
	case "process create":
		return issueCmd(ctx, rest, stdout, commands.ProcessCreate)
	case "bundle export":
		return bundleExport(ctx, rest, stdout)
	case "bundle verify":
		return bundleVerify(ctx, rest, stdout)
	case "schema register":
		return schemaRegister(ctx, rest, stdin, stdout)
	case "chain subscribe":
		return chainSubscribe(ctx, rest, stdout)
	case "chain set-allow":
		return chainSetAllow(ctx, rest, stdout)
	default:
		return fmt.Errorf("unknown command %q %q\n%s", group, op, usage)
	}
}

// globalFlags registers --registry/--token (env-backed) on fs and returns the
// destinations.
func globalFlags(fs *flag.FlagSet) (registry, token *string) {
	registry = fs.String("registry", os.Getenv("PROVIN_REGISTRY"), "registry base URL (env PROVIN_REGISTRY)")
	token = fs.String("token", os.Getenv("PROVIN_TOKEN"), "L1 bearer token (env PROVIN_TOKEN)")
	return registry, token
}

// parse runs fs over args with single-print error discipline: the FlagSet's
// own output is discarded (main prints the returned error exactly once), and
// -h/--help prints usage to stdout and reports success via errHelp.
func parse(fs *flag.FlagSet, args []string, stdout io.Writer) error {
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stdout, usage)
			return errHelp
		}
		return fmt.Errorf("%s: %w\n%s", fs.Name(), err, usage)
	}
	return nil
}

// errHelp marks a successful -h/--help invocation (usage already printed).
var errHelp = errors.New("help requested")

func ownerInit(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("owner init", flag.ContinueOnError)
	registry, token := globalFlags(fs)
	did := fs.String("did", "", "owner DID to register (required)")
	key := fs.String("key", "", "path for the owner's JWK key file (required; created if absent, reused if present)")
	if err := parse(fs, args, stdout); err != nil {
		if errors.Is(err, errHelp) {
			return nil
		}
		return err
	}
	if *did == "" || *key == "" {
		return fmt.Errorf("owner init: --did and --key are required")
	}
	env := commands.Env{Registry: *registry, Token: *token, Stdout: stdout}
	return commands.OwnerInit(ctx, env, *did, *key)
}

func issueCmd(ctx context.Context, args []string, stdout io.Writer, create func(context.Context, commands.Env, string, string) error) error {
	fs := flag.NewFlagSet("create", flag.ContinueOnError)
	registry, token := globalFlags(fs)
	did := fs.String("did", "", "DID to issue (required)")
	ownerKey := fs.String("owner-key", "", "path to the owner's JWK key file (required)")
	if err := parse(fs, args, stdout); err != nil {
		if errors.Is(err, errHelp) {
			return nil
		}
		return err
	}
	if *did == "" || *ownerKey == "" {
		return fmt.Errorf("create: --did and --owner-key are required")
	}
	env := commands.Env{Registry: *registry, Token: *token, Stdout: stdout}
	return create(ctx, env, *did, *ownerKey)
}

func bundleExport(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("bundle export", flag.ContinueOnError)
	registry, token := globalFlags(fs)
	head := fs.String("head", "", "chain head content address sha256:<hex> (required)")
	out := fs.String("out", "", "bundle directory to create; must not exist (required)")
	didBases := map[string]string{}
	fs.Func("did-base", "map a registry id to a DID-resolution base URL, <registry>=<url> (repeatable; unmapped registries default to https://<registry>)", func(v string) error {
		reg, base, ok := strings.Cut(v, "=")
		if !ok || reg == "" || base == "" {
			return fmt.Errorf("want <registry>=<url>, got %q", v)
		}
		didBases[reg] = base
		return nil
	})
	aggregateComplete := fs.Bool("aggregate-complete", false, "walk through aggregate boundaries: bundle consumed sources so source commitments re-verify offline (complete w.r.t. the SIGNED claimed sets)")
	vcResolverBases := map[string]string{}
	fs.Func("vc-resolver-base", "override the DID-advertised #vc-resolver endpoint for a registry, <registry>=<url> (repeatable; the split-horizon seam — advertised URLs may be reachable only inside the emitting network)", func(v string) error {
		reg, base, ok := strings.Cut(v, "=")
		if !ok || reg == "" || base == "" {
			return fmt.Errorf("want <registry>=<url>, got %q", v)
		}
		vcResolverBases[reg] = base
		return nil
	})
	allowLoopback := fs.Bool("allow-loopback", false, "permit loopback DID-resolution targets (local development)")
	allowPrivate := fs.Bool("allow-private", false, "permit RFC 1918 private DID-resolution targets")
	maxDepth := fs.Int("max-depth", 0, "chain walk bound (0 = default)")
	if err := parse(fs, args, stdout); err != nil {
		if errors.Is(err, errHelp) {
			return nil
		}
		return err
	}
	if *head == "" || *out == "" {
		return fmt.Errorf("bundle export: --head and --out are required")
	}
	env := commands.Env{Registry: *registry, Token: *token, Stdout: stdout}
	return commands.BundleExport(ctx, env, commands.BundleExportConfig{
		Head:              *head,
		Out:               *out,
		DIDBases:          didBases,
		AllowLoopback:     *allowLoopback,
		AllowPrivate:      *allowPrivate,
		MaxDepth:          *maxDepth,
		AggregateComplete: *aggregateComplete,
		VCResolverBases:   vcResolverBases,
	})
}

func bundleVerify(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("bundle verify", flag.ContinueOnError)
	dir := fs.String("bundle", "", "bundle directory (required)")
	head := fs.String("head", "", "expected chain head sha256:<hex> — anchors what data flowed")
	digest := fs.String("digest", "", "expected bundle digest sha256:<hex> — anchors the whole archive, proofs and documents included")
	if err := parse(fs, args, stdout); err != nil {
		if errors.Is(err, errHelp) {
			return nil
		}
		return err
	}
	if *dir == "" {
		return fmt.Errorf("bundle verify: --bundle is required")
	}
	return commands.BundleVerify(ctx, commands.Env{Stdout: stdout}, commands.BundleVerifyConfig{
		Dir:    *dir,
		Head:   *head,
		Digest: *digest,
	})
}

func schemaRegister(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("schema register", flag.ContinueOnError)
	registry, token := globalFlags(fs)
	name := fs.String("name", "", "schema name (required)")
	format := fs.String("format", "", "schema format, e.g. JsonSchema (required; open string — the registry validates, the CLI does not enumerate)")
	file := fs.String("file", "", "path to the schema body, or - to read it from stdin (required)")
	prerelease := fs.String("prerelease", "", "optional prerelease label")
	if err := parse(fs, args, stdout); err != nil {
		if errors.Is(err, errHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("schema register: unexpected arguments %v\n%s", fs.Args(), usage)
	}
	if *name == "" || *format == "" {
		return fmt.Errorf("schema register: --name and --format are required")
	}
	if *file == "" {
		return fmt.Errorf("schema register: --file is required")
	}
	body, err := readFileOrStdin(*file, stdin)
	if err != nil {
		return fmt.Errorf("schema register: read %s: %w", *file, err)
	}
	env := commands.Env{Registry: *registry, Token: *token, Stdout: stdout}
	return commands.SchemaRegister(ctx, env, commands.SchemaRegisterConfig{
		Name:       *name,
		Format:     *format,
		Body:       body,
		Prerelease: *prerelease,
	})
}

// readFileOrStdin reads path's bytes, or stdin when path is "-" — the
// registration-from-a-pipe path the spec calls the common operator case.
func readFileOrStdin(path string, stdin io.Reader) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(stdin)
	}
	return os.ReadFile(path)
}

func chainSubscribe(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("chain subscribe", flag.ContinueOnError)
	registry, token := globalFlags(fs)
	subscriber := fs.String("subscriber", "", "subscriber DID (required)")
	publisher := fs.String("publisher", "", "publisher DID (required)")
	delivery := fs.String("delivery", "", "requested payload delivery: inline | by-reference (optional; omitted/empty means by-reference, the protocol's own default — the CLI passes it through and does not invent one)")
	if err := parse(fs, args, stdout); err != nil {
		if errors.Is(err, errHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("chain subscribe: unexpected arguments %v\n%s", fs.Args(), usage)
	}
	if *subscriber == "" || *publisher == "" {
		return fmt.Errorf("chain subscribe: --subscriber and --publisher are required")
	}
	env := commands.Env{Registry: *registry, Token: *token, Stdout: stdout}
	return commands.ChainSubscribe(ctx, env, commands.ChainSubscribeConfig{
		Subscriber: *subscriber,
		Publisher:  *publisher,
		Delivery:   *delivery,
	})
}

func chainSetAllow(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("chain set-allow", flag.ContinueOnError)
	registry, token := globalFlags(fs)
	pipeline := fs.String("pipeline", "", "pipeline DID whose allow-list is REPLACED (required)")
	var patterns []string
	fs.Func("pattern", "allow-list DID glob pattern (repeatable). UpdateAllowList is full-replacement: this REPLACES the entire allow-list, not an incremental add. At least one --pattern or --clear is required.", func(v string) error {
		if v == "" {
			return fmt.Errorf("must not be blank")
		}
		patterns = append(patterns, v)
		return nil
	})
	clearFlag := fs.Bool("clear", false, "REPLACE the allow-list with zero rules (an explicit deny-all); mutually exclusive with --pattern")
	if err := parse(fs, args, stdout); err != nil {
		if errors.Is(err, errHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("chain set-allow: unexpected arguments %v\n%s", fs.Args(), usage)
	}
	if *pipeline == "" {
		return fmt.Errorf("chain set-allow: --pipeline is required")
	}
	env := commands.Env{Registry: *registry, Token: *token, Stdout: stdout}
	return commands.ChainSetAllow(ctx, env, commands.ChainSetAllowConfig{
		Pipeline: *pipeline,
		Patterns: patterns,
		Clear:    *clearFlag,
	})
}
