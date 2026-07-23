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
	err := run(context.Background(), os.Args[1:], os.Stdin, os.Stdout)
	if err == nil {
		return
	}
	code, msg := exitCode(err)
	if msg != "" {
		fmt.Fprintln(os.Stderr, "provin:", msg)
	}
	os.Exit(code)
}

// exitCode maps a non-nil error from run() to a process exit code and an
// optional stderr message. A commands.ExitStatus (org verify's verdict-driven
// exit codes, spec cli-stage3-orgverify-port §7.2/§7.3) unwraps to its own
// Code and Message (Message is empty when the verdict was already reported
// on stdout — see commands.OrgVerify); every other error maps to exit 1 with
// its own text as the message. Commands never call os.Exit themselves — this
// is the single place a returned error becomes a process exit code, which is
// what keeps every command path testable via run() in-process.
func exitCode(err error) (code int, stderrMsg string) {
	var es commands.ExitStatus
	if errors.As(err, &es) {
		return es.Code, es.Message
	}
	return 1, err.Error()
}

const usage = `usage: provin <group> <operation> [flags]

Implemented:
  owner    init       --did <owner-did> --key <jwk-path>     register a pipeline owner
  pipeline create     --did <target-did> --owner-key <path> [--external-key <path>]  issue a pipeline DID
  process  create     --did <target-did> --owner-key <path> [--external-key <path>]  issue a process DID
                      (--external-key: register locally-minted public keys instead of the registry's own KMS mint — see deploy/quickstart)
  bundle   export     --head <sha256:hex> --out <dir>        archive a chain + its authority documents
                      [--aggregate-complete=false] [--did-base <registry>=<url>]... [--vc-resolver-base <registry>=<url>]... [--audit-base <registry>=<url>]...
                      [--allow-loopback] [--allow-private] [--max-depth <n>]
  bundle   verify     --bundle <dir> --head <sha256:hex> and/or --digest <sha256:hex>
                                                              re-verify a bundle offline (no network)
  schema   register   --name <name> --format <format> --file <path|-> [--prerelease <label>]
                                                              register an immutable schema version (- reads the body from stdin)
  chain    subscribe  --subscriber <did> --publisher <did> [--delivery inline|by-reference]
                                                              subscribe to a publisher (delivery mode is REQUESTED, never server-confirmed)
  chain    set-allow  --pipeline <did> --pattern <glob> [--pattern <glob>...] | --clear
                                                              REPLACE the pipeline's entire allow-list (full replacement; --clear for deny-all)
  chain    get-allow  --pipeline <did>                       print the pipeline's current allow-list (read-before-replace; needs the chain:read-allowlist grant)
  org      verify     --did <did>                            check DNS-based organization endorsement; exit code carries the verdict
  org      inspect    --did <did>                            show raw DNS / DID Document state for a DID, no verdict; always exits 0
  org      diagnose   --did <did>                            print the verdict plus remediation steps; always exits 0
  org      generate-txt --did <did> [--fingerprint sha256:<hex>]
                                                              print the DNS TXT record name + value that would endorse the DID
                                                              (--fingerprint skips DID resolution: offline mode, no --registry needed)
  evidence rotate     --dir <log-dir>                         seal the relationship-evidence log to a cold-archive segment and
                                                              start a fresh one (offline; stop the daemon first). Append-only:
                                                              records are archived, never deleted.

Global flags (owner/pipeline/process/bundle export/schema register/chain subscribe/chain set-allow):
  --registry <base-url>   registry base URL   (env PROVIN_REGISTRY)
  --token    <token>      L1 bearer token     (env PROVIN_TOKEN)

org verify/inspect/diagnose/generate-txt take --registry (env PROVIN_REGISTRY)
only — DID resolution is an unauthenticated public route, so no --token.
org verify's exit code maps the endorsement verdict: 0=verified 1=missing
2=invalid 3=unreachable 4=na. org inspect/diagnose/generate-txt exit 0 on
success regardless of the underlying state.`

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
	case "chain get-allow":
		return chainGetAllow(ctx, rest, stdout)
	case "org verify":
		return orgVerify(ctx, rest, stdout)
	case "org inspect":
		return orgInspect(ctx, rest, stdout)
	case "org diagnose":
		return orgDiagnose(ctx, rest, stdout)
	case "org generate-txt":
		return orgGenerateTXT(ctx, rest, stdout)
	case "evidence rotate":
		return evidenceRotate(ctx, rest, stdout)
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

func evidenceRotate(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("evidence rotate", flag.ContinueOnError)
	dir := fs.String("dir", "", "relationship-evidence log directory to rotate (required; stop the daemon first)")
	if err := parse(fs, args, stdout); err != nil {
		if errors.Is(err, errHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("evidence rotate: unexpected arguments %v\n%s", fs.Args(), usage)
	}
	if *dir == "" {
		return fmt.Errorf("evidence rotate: --dir is required")
	}
	return commands.EvidenceRotate(ctx, stdout, *dir)
}

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

func issueCmd(ctx context.Context, args []string, stdout io.Writer, create func(context.Context, commands.Env, string, string, *commands.ExternalKeys) error) error {
	fs := flag.NewFlagSet("create", flag.ContinueOnError)
	registry, token := globalFlags(fs)
	did := fs.String("did", "", "DID to issue (required)")
	ownerKey := fs.String("owner-key", "", "path to the owner's JWK key file (required)")
	externalKey := fs.String("external-key", "", "path to a JSON file of locally-minted public keys keyed by DID (external-key mode: the registry registers these public halves and never holds this DID's private keys — see deploy/quickstart's provisioner for a generator)")
	if err := parse(fs, args, stdout); err != nil {
		if errors.Is(err, errHelp) {
			return nil
		}
		return err
	}
	if *did == "" || *ownerKey == "" {
		return fmt.Errorf("create: --did and --owner-key are required")
	}
	var external *commands.ExternalKeys
	if *externalKey != "" {
		var err error
		external, err = commands.LoadExternalKeys(*externalKey, *did)
		if err != nil {
			return err
		}
	}
	env := commands.Env{Registry: *registry, Token: *token, Stdout: stdout}
	return create(ctx, env, *did, *ownerKey, external)
}

// bundleExportOpts carries bundle export's parsed flags. Split from
// bundleExport so a test can parse a flag-omitted invocation and assert the
// ACTUAL defaults (the usage text alone cannot pin them).
type bundleExportOpts struct {
	registry, token   *string
	head, out         *string
	didBases          map[string]string
	vcResolverBases   map[string]string
	auditBases        map[string]string
	aggregateComplete *bool
	allowLoopback     *bool
	allowPrivate      *bool
	maxDepth          *int
}

func bundleExportFlagSet() (*flag.FlagSet, *bundleExportOpts) {
	fs := flag.NewFlagSet("bundle export", flag.ContinueOnError)
	o := &bundleExportOpts{didBases: map[string]string{}, vcResolverBases: map[string]string{}, auditBases: map[string]string{}}
	o.registry, o.token = globalFlags(fs)
	o.head = fs.String("head", "", "chain head content address sha256:<hex> (required)")
	o.out = fs.String("out", "", "bundle directory to create; must not exist (required)")
	mapFlag := func(name, usage string, into map[string]string) {
		fs.Func(name, usage, func(v string) error {
			reg, base, ok := strings.Cut(v, "=")
			if !ok || reg == "" || base == "" {
				return fmt.Errorf("want <registry>=<url>, got %q", v)
			}
			into[reg] = base
			return nil
		})
	}
	mapFlag("did-base", "map a registry id to a DID-resolution base URL, <registry>=<url> (repeatable; unmapped registries default to https://<registry>)", o.didBases)
	mapFlag("vc-resolver-base", "override the DID-advertised #vc-resolver endpoint for a registry, <registry>=<url> (repeatable; the split-horizon seam — advertised URLs may be reachable only inside the emitting network)", o.vcResolverBases)
	mapFlag("audit-base", "override the DID-advertised #audit endpoint for a registry, <registry>=<url> (repeatable; audit-specific split-horizon — independent of --did-base)", o.auditBases)
	o.aggregateComplete = fs.Bool("aggregate-complete", true, "walk through aggregate boundaries: bundle consumed sources so source commitments re-verify offline (complete w.r.t. the SIGNED claimed sets). Default ON — pass =false for a v1 linear-only bundle (no receipt/source connectivity needed)")
	o.allowLoopback = fs.Bool("allow-loopback", false, "permit loopback DID-resolution targets (local development)")
	o.allowPrivate = fs.Bool("allow-private", false, "permit RFC 1918 private DID-resolution targets")
	o.maxDepth = fs.Int("max-depth", 0, "chain walk bound (0 = default)")
	return fs, o
}

func bundleExport(ctx context.Context, args []string, stdout io.Writer) error {
	fs, o := bundleExportFlagSet()
	registry, token := o.registry, o.token
	head, out := o.head, o.out
	didBases, vcResolverBases, auditBases := o.didBases, o.vcResolverBases, o.auditBases
	aggregateComplete := o.aggregateComplete
	allowLoopback, allowPrivate, maxDepth := o.allowLoopback, o.allowPrivate, o.maxDepth
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
		AuditBases:        auditBases,
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

func chainGetAllow(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("chain get-allow", flag.ContinueOnError)
	registry, token := globalFlags(fs)
	pipeline := fs.String("pipeline", "", "pipeline DID whose allow-list is read (required)")
	if err := parse(fs, args, stdout); err != nil {
		if errors.Is(err, errHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("chain get-allow: unexpected arguments %v\n%s", fs.Args(), usage)
	}
	if *pipeline == "" {
		return fmt.Errorf("chain get-allow: --pipeline is required")
	}
	env := commands.Env{Registry: *registry, Token: *token, Stdout: stdout}
	return commands.ChainGetAllow(ctx, env, *pipeline)
}

// registryFlag registers --registry (env-backed) on fs for the org commands,
// which need no bearer token: DID resolution is an unauthenticated public
// route (spec §7.4), so exposing --token here would be a footgun (a flag the
// operator sets that silently does nothing).
func registryFlag(fs *flag.FlagSet) *string {
	return fs.String("registry", os.Getenv("PROVIN_REGISTRY"), "registry base URL (env PROVIN_REGISTRY)")
}

func orgVerify(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("org verify", flag.ContinueOnError)
	registry := registryFlag(fs)
	did := fs.String("did", "", "DID to verify (required)")
	if err := parse(fs, args, stdout); err != nil {
		if errors.Is(err, errHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("org verify: unexpected arguments %v\n%s", fs.Args(), usage)
	}
	if *did == "" {
		return fmt.Errorf("org verify: --did is required")
	}
	env := commands.Env{Registry: *registry, Stdout: stdout}
	return commands.OrgVerify(ctx, env, commands.OrgVerifyConfig{DID: *did})
}

func orgInspect(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("org inspect", flag.ContinueOnError)
	registry := registryFlag(fs)
	did := fs.String("did", "", "DID to inspect (required)")
	if err := parse(fs, args, stdout); err != nil {
		if errors.Is(err, errHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("org inspect: unexpected arguments %v\n%s", fs.Args(), usage)
	}
	if *did == "" {
		return fmt.Errorf("org inspect: --did is required")
	}
	env := commands.Env{Registry: *registry, Stdout: stdout}
	return commands.OrgInspect(ctx, env, commands.OrgInspectConfig{DID: *did})
}

func orgDiagnose(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("org diagnose", flag.ContinueOnError)
	registry := registryFlag(fs)
	did := fs.String("did", "", "DID to diagnose (required)")
	if err := parse(fs, args, stdout); err != nil {
		if errors.Is(err, errHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("org diagnose: unexpected arguments %v\n%s", fs.Args(), usage)
	}
	if *did == "" {
		return fmt.Errorf("org diagnose: --did is required")
	}
	env := commands.Env{Registry: *registry, Stdout: stdout}
	return commands.OrgDiagnose(ctx, env, commands.OrgDiagnoseConfig{DID: *did})
}

func orgGenerateTXT(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("org generate-txt", flag.ContinueOnError)
	registry := registryFlag(fs)
	did := fs.String("did", "", "DID to generate a TXT record for (required)")
	fingerprint := fs.String("fingerprint", "", "key fingerprint sha256:<hex> (optional; when set, skips DID resolution — offline mode, no --registry needed)")
	if err := parse(fs, args, stdout); err != nil {
		if errors.Is(err, errHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("org generate-txt: unexpected arguments %v\n%s", fs.Args(), usage)
	}
	if *did == "" {
		return fmt.Errorf("org generate-txt: --did is required")
	}
	env := commands.Env{Registry: *registry, Stdout: stdout}
	return commands.OrgGenerateTXT(ctx, env, commands.OrgGenerateTXTConfig{DID: *did, Fingerprint: *fingerprint})
}
