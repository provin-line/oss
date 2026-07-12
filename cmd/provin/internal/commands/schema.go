package commands

import (
	"context"
	"fmt"

	"connectrpc.com/connect"

	schemapb "github.com/provin-line/oss/gen/go/dplaax/schema/v1"
)

// SchemaRegisterConfig carries `provin schema register`'s inputs beyond the
// global environment. Name and Format are required (checked by the caller
// before this reaches the wire); Body is the already-read schema document
// (from --file or stdin) and must not be empty.
type SchemaRegisterConfig struct {
	Name       string
	Format     string
	Body       []byte
	Prerelease string
}

// SchemaRegister appends a new immutable schema version and prints the
// server-assigned version — echoing it back is the command's whole value,
// since the version is content-addressed and cannot be predicted client-side.
func SchemaRegister(ctx context.Context, env Env, cfg SchemaRegisterConfig) error {
	if len(cfg.Body) == 0 {
		return fmt.Errorf("schema register: schema body must not be empty")
	}
	c, err := env.schemaClient()
	if err != nil {
		return err
	}
	res, err := c.RegisterSchema(ctx, connect.NewRequest(&schemapb.RegisterSchemaRequest{
		Name:         cfg.Name,
		SchemaFormat: cfg.Format,
		SchemaBody:   cfg.Body,
		Prerelease:   cfg.Prerelease,
	}))
	if err != nil {
		return fmt.Errorf("schema register: %w", err)
	}
	fmt.Fprintf(env.out(), "registered schema %s@%s\n", cfg.Name, res.Msg.GetSchema().GetVersion())
	return nil
}
