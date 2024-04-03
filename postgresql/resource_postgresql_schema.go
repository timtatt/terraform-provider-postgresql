package postgresql

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"reflect"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/lib/pq"
	acl "github.com/sean-/postgresql-acl"
)

const (
	schemaNameAttr     = "name"
	schemaDatabaseAttr = "database"
	schemaOwnerAttr    = "owner"
	schemaPolicyAttr   = "policy"
	schemaIfNotExists  = "if_not_exists"
	schemaDropCascade  = "drop_cascade"

	schemaPolicyCreateAttr          = "create"
	schemaPolicyCreateWithGrantAttr = "create_with_grant"
	schemaPolicyRoleAttr            = "role"
	schemaPolicyUsageAttr           = "usage"
	schemaPolicyUsageWithGrantAttr  = "usage_with_grant"
)

var _ resource.Resource = &ResourcePostgreSQLSchema{}
var _ resource.ResourceWithConfigure = &ResourcePostgreSQLSchema{}

func NewResourceSchema() resource.Resource {
	return &ResourcePostgreSQLSchema{}
}

type ResourcePostgreSQLSchema struct {
	db *DBConnection
}

type ResourcePostgreSQLSchemaPolicyModel struct {
	Create          types.Bool   `tfsdk:"create"`
	CreateWithGrant types.Bool   `tfsdk:"create_with_grant"`
	Role            types.String `tfsdk:"role"`
	Usage           types.Bool   `tfsdk:"usage"`
	UsageWithGrant  types.Bool   `tfsdk:"usage_with_grant"`
}

type ResourcePostgreSQLSchemaModel struct {
	Id          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Database    types.String `tfsdk:"database"`
	Owner       types.String `tfsdk:"owner"`
	IfNotExists types.Bool   `tfsdk:"if_not_exists"`
	DropCascade types.Bool   `tfsdk:"drop_cascade"`
	Policies    types.Set    `tfsdk:"policy"`
}

// Create: PGResourceFunc(resourcePostgreSQLSchemaCreate),
// Read:   PGResourceFunc(resourcePostgreSQLSchemaRead),
// Update: PGResourceFunc(resourcePostgreSQLSchemaUpdate),
// Delete: PGResourceFunc(resourcePostgreSQLSchemaDelete),
// Exists: PGResourceExistsFunc(resourcePostgreSQLSchemaExists),
// Importer: &schema.ResourceImporter{
// 	StateContext: schema.ImportStatePassthroughContext,
// },

func (r *ResourcePostgreSQLSchema) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_schema"
}

func (r *ResourcePostgreSQLSchema) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "The name of the schema",
			},
			"database": schema.StringAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "The database name to alter schema",
			},
			"owner": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "The ROLE name who owns the schema",
			},
			"if_not_exists": schema.BoolAttribute{
				Computed:    true,
				Optional:    true,
				Default:     booldefault.StaticBool(true),
				Description: "When true, use the existing schema if it exists",
			},
			"drop_cascade": schema.BoolAttribute{
				Computed:    true,
				Optional:    true,
				Default:     booldefault.StaticBool(false),
				Description: "When true, will also drop all the objects that are contained in the schema",
			},
		},
		Blocks: map[string]schema.Block{
			"policy": schema.SetNestedBlock{
				DeprecationMessage: "Use postgresql_grant resource instead (with object_type=\"schema\")",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"create": schema.BoolAttribute{
							Computed:    true,
							Optional:    true,
							Default:     booldefault.StaticBool(false),
							Description: "If true, allow the specified ROLEs to CREATE new objects within the schema(s)",
						},
						"create_with_grant": schema.BoolAttribute{
							Computed:    true,
							Optional:    true,
							Default:     booldefault.StaticBool(false),
							Description: "If true, allow the specified ROLEs to CREATE new objects within the schema(s) and GRANT the same CREATE privilege to different ROLEs",
						},
						"role": schema.StringAttribute{
							Computed:    true,
							Optional:    true,
							Default:     stringdefault.StaticString(""),
							Description: "ROLE who will receive this policy (default: PUBLIC)",
						},
						"usage": schema.BoolAttribute{
							Computed:    true,
							Optional:    true,
							Default:     booldefault.StaticBool(false),
							Description: "If true, allow the specified ROLEs to use objects within the schema(s)",
						},
						"usage_with_grant": schema.BoolAttribute{
							Computed:    true,
							Optional:    true,
							Default:     booldefault.StaticBool(false),
							Description: "If true, allow the specified ROLEs to use objects within the schema(s) and GRANT the same USAGE privilege to different ROLEs",
						},
					},
				},
			},
		},
	}
}

func (r *ResourcePostgreSQLSchema) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	db, err := GetDBConnection(req.ProviderData)

	if err != nil {
		resp.Diagnostics.AddError("Failed to establish DB connection", err.Error())
		return
	}

	r.db = db
}

func (r *ResourcePostgreSQLSchema) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ResourcePostgreSQLSchemaModel
	req.Config.Get(ctx, &data)

	if resp.Diagnostics.HasError() {
		return
	}

	database := getDatabaseName(&data.Database, r.db.client.databaseName)
	txn, err := startTransaction(r.db.client, database)
	if err != nil {
		resp.Diagnostics.AddError("unable to start transaction", err.Error())
		return
	}
	defer deferredRollback(txn)

	// If the authenticated user is not a superuser (e.g. on AWS RDS)
	// we'll need to temporarily grant it membership in the following roles:
	//  * the owner of the db (to have the permissions to create the schema)
	//  * the owner of the schema, if it has one (in order to change its owner)
	var rolesToGrant []string

	dbOwner, err := getDatabaseOwner(txn, database)
	if err != nil {
		resp.Diagnostics.AddError("unable to get database owner", err.Error())
		return
	}
	rolesToGrant = append(rolesToGrant, dbOwner)

	schemaOwner := data.Owner.ValueString()
	if schemaOwner != "" && schemaOwner != dbOwner {
		rolesToGrant = append(rolesToGrant, schemaOwner)
	}

	err = withRolesGranted(txn, rolesToGrant, func() error {
		return createSchema(r.db, txn, &data)
	})

	if err != nil {
		resp.Diagnostics.AddError("unable to grant roles", err.Error())
		return
	}

	if err := txn.Commit(); err != nil {
		resp.Diagnostics.AddError("error committing schema", err.Error())
		return
	}

	readSchema(r.db, &data)

	resp.Diagnostics.Append(resp.State.Set(ctx, data)...)
}

func createSchema(db *DBConnection, txn *sql.Tx, schema *ResourcePostgreSQLSchemaModel) error {
	schemaName := schema.Name.ValueString()

	// Check if previous tasks haven't already create schema
	var foundSchema bool
	err := txn.QueryRow(`SELECT TRUE FROM pg_catalog.pg_namespace WHERE nspname = $1`, schemaName).Scan(&foundSchema)

	queries := []string{}
	switch {
	case err == sql.ErrNoRows:
		b := bytes.NewBufferString("CREATE SCHEMA ")
		if db.featureSupported(featureSchemaCreateIfNotExist) {
			if schema.IfNotExists.ValueBool() {
				fmt.Fprint(b, "IF NOT EXISTS ")
			}
		}
		fmt.Fprint(b, pq.QuoteIdentifier(schemaName))

		switch v, ok := schema.Owner.ValueString(), !schema.Owner.IsNull(); {
		case ok:
			fmt.Fprint(b, " AUTHORIZATION ", pq.QuoteIdentifier(v))
		}
		queries = append(queries, b.String())

	case err != nil:
		return fmt.Errorf("Error looking for schema: %w", err)

	default:
		// The schema already exists, we just set the owner.
		if err := setSchemaOwner(txn, schemaName, schema.Owner.ValueString()); err != nil {
			return err
		}
	}

	// ACL objects that can generate the necessary SQL
	type RoleKey string
	var schemaPolicies map[RoleKey]acl.Schema

	schema.Policies.Elements()

	for _, policy := range schema.Policies {
		rolePolicy := schemaPolicyToACL(&policy)

		roleKey := RoleKey(strings.ToLower(rolePolicy.Role))
		if existingRolePolicy, ok := schemaPolicies[roleKey]; ok {
			schemaPolicies[roleKey] = existingRolePolicy.Merge(rolePolicy)
		} else {
			schemaPolicies[roleKey] = rolePolicy
		}
	}

	for _, policy := range schemaPolicies {
		queries = append(queries, policy.Grants(schemaName)...)
	}

	for _, query := range queries {
		if _, err = txn.Exec(query); err != nil {
			return fmt.Errorf("Error creating schema %s: %w", schemaName, err)
		}
	}

	return nil
}

func (r *ResourcePostgreSQLSchema) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data ResourcePostgreSQLSchemaModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	database := getDatabaseName(&data.Database, r.db.client.databaseName)

	txn, err := startTransaction(r.db.client, database)
	if err != nil {
		resp.Diagnostics.AddError("unable to start transaction", err.Error())
		return
	}
	defer deferredRollback(txn)

	schemaName := data.Name.ValueString()

	exists, err := schemaExists(txn, schemaName)
	if err != nil {
		resp.Diagnostics.AddError("unable to check if schema exists", err.Error())
		return
	}

	if !exists {
		return
	}

	owner := data.Owner.ValueString()

	if err = withRolesGranted(txn, []string{owner}, func() error {
		dropMode := "RESTRICT"
		if data.DropCascade.ValueBool() {
			dropMode = "CASCADE"
		}

		sql := fmt.Sprintf("DROP SCHEMA %s %s", pq.QuoteIdentifier(schemaName), dropMode)
		if _, err = txn.Exec(sql); err != nil {
			return fmt.Errorf("Error deleting schema: %w", err)
		}

		return nil
	}); err != nil {
		resp.Diagnostics.AddError("unable to grant roles for schema", err.Error())
		return
	}

	if err := txn.Commit(); err != nil {
		resp.Diagnostics.AddError("error committing schema", err.Error())
		return
	}

}

func (r *ResourcePostgreSQLSchema) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data ResourcePostgreSQLSchemaModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	readSchema(r.db, &data)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func readSchema(db *DBConnection, schema *ResourcePostgreSQLSchemaModel) error {
	database, schemaName, err := getDBSchemaName(schema, db.client.databaseName)
	if err != nil {
		return err
	}

	txn, err := startTransaction(db.client, database)
	if err != nil {
		return err
	}
	defer deferredRollback(txn)

	var schemaOwner string
	var schemaACLs []string
	err = txn.QueryRow("SELECT pg_catalog.pg_get_userbyid(n.nspowner), COALESCE(n.nspacl, '{}'::aclitem[])::TEXT[] FROM pg_catalog.pg_namespace n WHERE n.nspname=$1", schemaName).Scan(&schemaOwner, pq.Array(&schemaACLs))
	switch {
	case err == sql.ErrNoRows:
		log.Printf("[WARN] PostgreSQL schema (%s) not found in database %s", schemaName, database)
		schema.Id = types.StringValue("")
		return nil
	case err != nil:
		return fmt.Errorf("Error reading schema: %w", err)
	default:
		type RoleKey string
		schemaPolicies := make(map[RoleKey]acl.Schema, len(schemaACLs))
		for _, aclStr := range schemaACLs {
			aclItem, err := acl.Parse(aclStr)
			if err != nil {
				return fmt.Errorf("Error parsing aclitem: %w", err)
			}

			schemaACL, err := acl.NewSchema(aclItem)
			if err != nil {
				return fmt.Errorf("invalid perms for schema: %w", err)
			}

			roleKey := RoleKey(strings.ToLower(schemaACL.Role))
			var mergedPolicy acl.Schema
			if existingRolePolicy, ok := schemaPolicies[roleKey]; ok {
				mergedPolicy = existingRolePolicy.Merge(schemaACL)
			} else {
				mergedPolicy = schemaACL
			}
			schemaPolicies[roleKey] = mergedPolicy
		}

		schema.Name = types.StringValue(schemaName)
		schema.Owner = types.StringValue(schemaOwner)
		schema.Database = types.StringValue(database)
		schema.Id = types.StringValue(generateSchemaID(schema, database))

		return nil
	}
}

func (r *ResourcePostgreSQLSchema) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var planData, stateData ResourcePostgreSQLSchemaModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &planData)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &stateData)...)

	if resp.Diagnostics.HasError() {
		return
	}

	databaseName := getDatabaseName(&planData.Database, r.db.client.databaseName)

	txn, err := startTransaction(r.db.client, databaseName)
	if err != nil {
		resp.Diagnostics.AddError("unable to start transaction", err.Error())
		return
	}
	defer deferredRollback(txn)

	schemaName := planData.Name.ValueString()
	if !planData.Name.Equal(stateData.Name) {
		oldSchemaName := stateData.Name.ValueString()
		tflog.Info(ctx, fmt.Sprintf("renaming schema from %s to %s", oldSchemaName, schemaName))
		if err := setSchemaName(txn, oldSchemaName, schemaName, databaseName); err != nil {
			resp.Diagnostics.AddError("unable to alter schema name", err.Error())
			return
		}
		stateData.Id = types.StringValue(generateSchemaID(&planData, databaseName))
	}

	if !planData.Owner.Equal(stateData.Owner) {
		newOwnerName := planData.Owner.ValueString()
		if err := setSchemaOwner(txn, schemaName, newOwnerName); err != nil {
			resp.Diagnostics.AddError("unable to set schema owner", err.Error())
			return
		}
	}

	if !planData.Policies.Equal(stateData.Policies) {
		if err := setSchemaPolicy(txn, schemaName, &planData.Policies, &stateData.Policies); err != nil {
			resp.Diagnostics.AddError("unable to update schema policy", err.Error())
			return
		}
	}

	if err := txn.Commit(); err != nil {
		resp.Diagnostics.AddError("error committing schema", err.Error())
		return
	}

	readSchema(r.db, &planData)
}

func setSchemaName(txn *sql.Tx, oldSchemaName string, newSchemaName string, databaseName string) error {
	if newSchemaName == "" {
		return errors.New("Error setting schema name to an empty string")
	}

	sql := fmt.Sprintf("ALTER SCHEMA %s RENAME TO %s", pq.QuoteIdentifier(oldSchemaName), pq.QuoteIdentifier(newSchemaName))
	if _, err := txn.Exec(sql); err != nil {
		return fmt.Errorf("Error updating schema NAME: %w", err)
	}

	return nil
}

func setSchemaOwner(txn *sql.Tx, schemaName string, schemaOwner string) error {
	if schemaOwner == "" {
		return errors.New("Error setting schema owner to an empty string")
	}

	sql := fmt.Sprintf("ALTER SCHEMA %s OWNER TO %s", pq.QuoteIdentifier(schemaName), pq.QuoteIdentifier(schemaOwner))
	if _, err := txn.Exec(sql); err != nil {
		return fmt.Errorf("Error updating schema OWNER: %w", err)
	}

	return nil
}

func setSchemaPolicy(txn *sql.Tx, schemaName string, schemaOwner string, newPolicies types.Set, oldPolicies types.Set) error {

	oldList := oldPolicies.Elements()
	newList := newPolicies.Elements().([]ResourcePostgreSQLSchemaPolicyModel)
	queries := make([]string, 0, len(oldList)+len(newList))
	dropped, added, updated, _ := schemaChangedPolicies(newPolicies.Elements(), newList)

	for _, p := range dropped {
		pMap := p.(map[string]interface{})
		rolePolicy := schemaPolicyToACL(pMap)

		// The PUBLIC role can not be DROP'ed, therefore we do not need
		// to prevent revoking against it not existing.
		if rolePolicy.Role != "" {
			var foundUser bool
			err := txn.QueryRow(`SELECT TRUE FROM pg_catalog.pg_roles WHERE rolname = $1`, rolePolicy.Role).Scan(&foundUser)
			switch {
			case err == sql.ErrNoRows:
				// Don't execute this role's REVOKEs because the role
				// was dropped first and therefore doesn't exist.
			case err != nil:
				return fmt.Errorf("Error reading schema: %w", err)
			default:
				queries = append(queries, rolePolicy.Revokes(schemaName)...)
			}
		}
	}

	for _, p := range added {
		pMap := p.(map[string]interface{})
		rolePolicy := schemaPolicyToACL(pMap)
		queries = append(queries, rolePolicy.Grants(schemaName)...)
	}

	for _, p := range updated {
		policies := p.([]interface{})
		if len(policies) != 2 {
			panic("expected 2 policies, old and new")
		}

		{
			oldPolicies := policies[0].(map[string]interface{})
			rolePolicy := schemaPolicyToACL(oldPolicies)
			queries = append(queries, rolePolicy.Revokes(schemaName)...)
		}

		{
			newPolicies := policies[1].(map[string]interface{})
			rolePolicy := schemaPolicyToACL(newPolicies)
			queries = append(queries, rolePolicy.Grants(schemaName)...)
		}
	}

	rolesToGrant := []string{}
	if !schema.Owner.IsNull() {
		rolesToGrant = append(rolesToGrant, schema.Owner.ValueString())
	}

	return withRolesGranted(txn, rolesToGrant, func() error {
		for _, query := range queries {
			if _, err := txn.Exec(query); err != nil {
				return fmt.Errorf("Error updating schema DCL: %w", err)
			}
		}
		return nil
	})
	return nil
}

// schemaChangedPolicies walks old and new to create a set of queries that can
// be executed to enact each type of state change (roles that have been dropped
// from the policy, added to a policy, have updated privilges, or are
// unchanged).
func schemaChangedPolicies(old, new []*ResourcePostgreSQLSchemaPolicyModel) (dropped, added, update, unchanged map[string]*ResourcePostgreSQLSchemaPolicyModel) {
	type RoleKey string
	oldLookupMap := make(map[RoleKey]*ResourcePostgreSQLSchemaPolicyModel, len(old))
	for idx := range old {
		v := old[idx]
		if !v.Role.IsNull() {
			roleKey := strings.ToLower(v.Role.ValueString())
			oldLookupMap[RoleKey(roleKey)] = v
		}
	}

	newLookupMap := make(map[RoleKey]*ResourcePostgreSQLSchemaPolicyModel, len(new))
	for idx := range new {
		v := new[idx]
		if !v.Role.IsNull() {
			roleKey := strings.ToLower(v.Role.ValueString())
			newLookupMap[RoleKey(roleKey)] = v
		}
	}

	droppedRoles := make(map[string]*ResourcePostgreSQLSchemaPolicyModel, len(old))
	for kOld, vOld := range oldLookupMap {
		if _, ok := newLookupMap[kOld]; !ok {
			droppedRoles[string(kOld)] = vOld
		}
	}

	addedRoles := make(map[string]*ResourcePostgreSQLSchemaPolicyModel, len(new))
	for kNew, vNew := range newLookupMap {
		if _, ok := oldLookupMap[kNew]; !ok {
			addedRoles[string(kNew)] = vNew
		}
	}

	updatedRoles := make(map[string]*ResourcePostgreSQLSchemaPolicyModel, len(new))
	unchangedRoles := make(map[string]*ResourcePostgreSQLSchemaPolicyModel, len(new))
	for kOld, vOld := range oldLookupMap {
		if vNew, ok := newLookupMap[kOld]; ok {
			if reflect.DeepEqual(vOld, vNew) {
				unchangedRoles[string(kOld)] = vOld
			} else {
				updatedRoles[string(kOld)] = []*ResourcePostgreSQLSchemaPolicyModel{vOld, vNew}
			}
		}
	}

	return droppedRoles, addedRoles, updatedRoles, unchangedRoles
}

func schemaPolicyToACL(policy *ResourcePostgreSQLSchemaPolicyModel) acl.Schema {
	var rolePolicy acl.Schema

	if policy.Create.ValueBool() {
		rolePolicy.Privileges |= acl.Create
	}

	if policy.CreateWithGrant.ValueBool() {
		rolePolicy.Privileges |= acl.Create
		rolePolicy.GrantOptions |= acl.Create
	}

	if policy.Usage.ValueBool() {
		rolePolicy.Privileges |= acl.Usage
	}

	if policy.UsageWithGrant.ValueBool() {
		rolePolicy.Privileges |= acl.Usage
		rolePolicy.GrantOptions |= acl.Usage
	}

	if !policy.Role.IsNull() {
		rolePolicy.Role = policy.Role.ValueString()
	}

	return rolePolicy
}

func generateSchemaID(schema *ResourcePostgreSQLSchemaModel, databaseName string) string {
	SchemaID := strings.Join([]string{
		getDatabaseName(&schema.Database, databaseName),
		schema.Name.ValueString(),
	}, ".")

	return SchemaID
}

func getDBSchemaName(schema *ResourcePostgreSQLSchemaModel, databaseName string) (string, string, error) {
	database := getDatabaseName(&schema.Database, databaseName)
	schemaName := schema.Name.ValueString()
	id := schema.Id.ValueString()

	// When importing, we have to parse the ID to find schema and database names.
	if schemaName == "" {
		parsed := strings.Split(id, ".")
		if len(parsed) != 2 {
			return "", "", fmt.Errorf("schema ID %s has not the expected format 'database.schema': %v", id, parsed)
		}
		database = parsed[0]
		schemaName = parsed[1]
	}
	return database, schemaName, nil
}
