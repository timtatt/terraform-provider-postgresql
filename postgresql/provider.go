package postgresql

import (
	"context"
	"fmt"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/blang/semver"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	sdkSchema "github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"golang.org/x/oauth2/google"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
)

const (
	defaultProviderMaxOpenConnections = 20
	defaultExpectedPostgreSQLVersion  = "9.0.0"
)

// Terraform Framework Support
var _ provider.Provider = &PostgresqlProvider{}

type PostgresqlProvider struct {
}

type PostgresProviderConfig struct {
	Scheme            types.String `tfsdk:"scheme"`
	Host              types.String `tfsdk:"host"`
	Port              types.Int64  `tfsdk:"port"`
	Database          types.String `tfsdk:"database"`
	Username          types.String `tfsdk:"username"`
	Password          types.String `tfsdk:"password"`
	AwsRdsIamAuth     types.Bool   `tfsdk:"aws_rds_iam_auth"`
	AwsRdsIamProfile  types.String `tfsdk:"aws_rds_iam_profile"`
	AwsRdsIamRegion   types.String `tfsdk:"aws_rds_iam_region"`
	AzureIdentityAuth types.Bool   `tfsdk:"azure_identity_auth"`
	AzureTenantId     types.String `tfsdk:"azure_tenant_id"`
	DatabaseUsername  types.String `tfsdk:"database_username"`
	Superuser         types.Bool   `tfsdk:"superuser"`
	SslMode           types.String `tfsdk:"sslmode"`
	SslRootCert       types.String `tfsdk:"sslrootcert"`
	ConnectTimeout    types.Int64  `tfsdk:"connect_timeout"`
	MaxConnections    types.Int64  `tfsdk:"max_connections"`
	ExpectedVersion   types.String `tfsdk:"expected_version"`
	ClientCert        types.List   `tfsdk:"clientcert"`
}

func New() provider.Provider {
	return &PostgresqlProvider{}
}

func (p *PostgresqlProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "postgresql"
}

func (p *PostgresqlProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"scheme": schema.StringAttribute{
				Optional: true,
				Validators: []validator.String{
					stringvalidator.OneOf(
						"postgres",
						"awspostgres",
						"gcppostgres",
					),
				},
			},
			"host": schema.StringAttribute{
				Optional:    true,
				Description: "Name of PostgreSQL server address to connect to",
			},
			"port": schema.Int64Attribute{
				Optional:    true,
				Description: "The PostgreSQL port number to connect to at the server host, or socket file name extension for Unix-domain connections",
			},
			"database": schema.StringAttribute{
				Optional:    true,
				Description: "The name of the database to connect to in order to conenct to (defaults to `postgres`).",
			},
			"username": schema.StringAttribute{
				Optional:    true,
				Description: "PostgreSQL user name to connect as",
			},
			"password": schema.StringAttribute{
				Optional:    true,
				Description: "Password to be used if the PostgreSQL server demands password authentication",
				Sensitive:   true,
			},

			"aws_rds_iam_auth": schema.BoolAttribute{
				Optional: true,
				Description: "Use rds_iam instead of password authentication " +
					"(see: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html)",
			},

			"aws_rds_iam_profile": schema.StringAttribute{
				Optional:    true,
				Description: "AWS profile to use for IAM auth",
			},

			"aws_rds_iam_region": schema.StringAttribute{
				Optional:    true,
				Description: "AWS region to use for IAM auth",
			},

			"azure_identity_auth": schema.BoolAttribute{
				Optional: true,
				Description: "Use MS Azure identity OAuth token " +
					"(see: https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/how-to-configure-sign-in-azure-ad-authentication)",
			},

			"azure_tenant_id": schema.StringAttribute{
				Optional:    true,
				Description: "MS Azure tenant ID (see: https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/client_config.html)",
			},

			// Conection username can be different than database username with user name mapas (e.g.: in Azure)
			// See https://www.postgresql.org/docs/current/auth-username-maps.html
			"database_username": schema.StringAttribute{
				Optional:    true,
				Description: "Database username associated to the connected user (for user name maps)",
			},

			"superuser": schema.BoolAttribute{
				Optional: true,
				Description: "Specify if the user to connect as is a Postgres superuser or not." +
					"If not, some feature might be disabled (e.g.: Refreshing state password from Postgres)",
			},

			"sslmode": schema.StringAttribute{
				Optional:    true,
				Description: "This option determines whether or with what priority a secure SSL TCP/IP connection will be negotiated with the PostgreSQL server",
			},
			"sslrootcert": schema.StringAttribute{
				Description: "The SSL server root certificate file path. The file must contain PEM encoded data.",
				Optional:    true,
			},

			"connect_timeout": schema.Int64Attribute{
				Optional:    true,
				Description: "Maximum wait for connection, in seconds. Zero or not specified means wait indefinitely.",
				Validators: []validator.Int64{
					int64validator.AtLeast(-1),
				},
			},
			"max_connections": schema.Int64Attribute{
				Optional:    true,
				Description: "Maximum number of connections to establish to the database. Zero means unlimited.",
				Validators: []validator.Int64{
					int64validator.AtLeast(-1),
				},
			},
			"expected_version": schema.StringAttribute{
				Optional:    true,
				Description: "Specify the expected version of PostgreSQL.",
				Validators:  []validator.String{
					// TODO add validator for version
				},
			},
		},
		Blocks: map[string]schema.Block{
			"clientcert": schema.ListNestedBlock{
				Description: "SSL client certificate if required by the database.",
				Validators: []validator.List{
					listvalidator.SizeAtMost(1),
				},
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"cert": schema.StringAttribute{
							Description: "The SSL client certificate file path. The file must contain PEM encoded data.",
							Required:    true,
						},
						"key": schema.StringAttribute{
							Description: "The SSL client certificate private key file path. The file must contain PEM encoded data.",
							Required:    true,
						},
						"sslinline": schema.BoolAttribute{
							Description: "Must be set to true if you are inlining the cert/key instead of using a file path.",
							Optional:    true,
						},
					},
				},
			},
		},
	}
}

func (p *PostgresqlProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {

	var config PostgresProviderConfig

	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)

	if resp.Diagnostics.HasError() {
		return
	}

	client, err := getDBClient(&config)

	if err != nil {
		resp.Diagnostics.AddError("unable to configure db client2", err.Error())
		return
	}

	tflog.Info(ctx, "Adding DB client to ResourceData and DataSourceData")

	resp.ResourceData = client
	resp.DataSourceData = client
}

func (p *PostgresqlProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{}
}

func (p *PostgresqlProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{}
}

// Legacy Terraform SDKv2 Support
// Provider returns a terraform.ResourceProvider.
func Provider() *sdkSchema.Provider {
	return &sdkSchema.Provider{
		Schema: map[string]*sdkSchema.Schema{
			"scheme": {
				Type:     sdkSchema.TypeString,
				Optional: true,
				ValidateFunc: validation.StringInSlice([]string{
					"postgres",
					"awspostgres",
					"gcppostgres",
				}, false),
			},
			"host": {
				Type:        sdkSchema.TypeString,
				Optional:    true,
				Description: "Name of PostgreSQL server address to connect to",
			},
			"port": {
				Type:        sdkSchema.TypeInt,
				Optional:    true,
				Description: "The PostgreSQL port number to connect to at the server host, or socket file name extension for Unix-domain connections",
			},
			"database": {
				Type:        sdkSchema.TypeString,
				Optional:    true,
				Description: "The name of the database to connect to in order to conenct to (defaults to `postgres`).",
			},
			"username": {
				Type:        sdkSchema.TypeString,
				Optional:    true,
				Description: "PostgreSQL user name to connect as",
			},
			"password": {
				Type:        sdkSchema.TypeString,
				Optional:    true,
				Description: "Password to be used if the PostgreSQL server demands password authentication",
				Sensitive:   true,
			},

			"aws_rds_iam_auth": {
				Type:     sdkSchema.TypeBool,
				Optional: true,
				Description: "Use rds_iam instead of password authentication " +
					"(see: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html)",
			},

			"aws_rds_iam_profile": {
				Type:        sdkSchema.TypeString,
				Optional:    true,
				Description: "AWS profile to use for IAM auth",
			},

			"aws_rds_iam_region": {
				Type:        sdkSchema.TypeString,
				Optional:    true,
				Description: "AWS region to use for IAM auth",
			},

			"azure_identity_auth": {
				Type:     sdkSchema.TypeBool,
				Optional: true,
				Description: "Use MS Azure identity OAuth token " +
					"(see: https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/how-to-configure-sign-in-azure-ad-authentication)",
			},

			"azure_tenant_id": {
				Type:        sdkSchema.TypeString,
				Optional:    true,
				Description: "MS Azure tenant ID (see: https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/client_config.html)",
			},

			// Conection username can be different than database username with user name mapas (e.g.: in Azure)
			// See https://www.postgresql.org/docs/current/auth-username-maps.html
			"database_username": {
				Type:        sdkSchema.TypeString,
				Optional:    true,
				Description: "Database username associated to the connected user (for user name maps)",
			},

			"superuser": {
				Type:     sdkSchema.TypeBool,
				Optional: true,
				Description: "Specify if the user to connect as is a Postgres superuser or not." +
					"If not, some feature might be disabled (e.g.: Refreshing state password from Postgres)",
			},

			"sslmode": {
				Type:        sdkSchema.TypeString,
				Optional:    true,
				Description: "This option determines whether or with what priority a secure SSL TCP/IP connection will be negotiated with the PostgreSQL server",
			},
			"clientcert": {
				Type:        sdkSchema.TypeList,
				Optional:    true,
				Description: "SSL client certificate if required by the database.",
				Elem: &sdkSchema.Resource{
					Schema: map[string]*sdkSchema.Schema{
						"cert": {
							Type:        sdkSchema.TypeString,
							Description: "The SSL client certificate file path. The file must contain PEM encoded data.",
							Required:    true,
						},
						"key": {
							Type:        sdkSchema.TypeString,
							Description: "The SSL client certificate private key file path. The file must contain PEM encoded data.",
							Required:    true,
						},
						"sslinline": {
							Type:        sdkSchema.TypeBool,
							Description: "Must be set to true if you are inlining the cert/key instead of using a file path.",
							Optional:    true,
						},
					},
				},
				MaxItems: 1,
			},
			"sslrootcert": {
				Type:        sdkSchema.TypeString,
				Description: "The SSL server root certificate file path. The file must contain PEM encoded data.",
				Optional:    true,
			},

			"connect_timeout": {
				Type:         sdkSchema.TypeInt,
				Optional:     true,
				Description:  "Maximum wait for connection, in seconds. Zero or not specified means wait indefinitely.",
				ValidateFunc: validation.IntAtLeast(-1),
			},
			"max_connections": {
				Type:         sdkSchema.TypeInt,
				Optional:     true,
				Description:  "Maximum number of connections to establish to the database. Zero means unlimited.",
				ValidateFunc: validation.IntAtLeast(-1),
			},
			"expected_version": {
				Type:         sdkSchema.TypeString,
				Optional:     true,
				Description:  "Specify the expected version of PostgreSQL.",
				ValidateFunc: validateExpectedVersion,
			},
		},

		ResourcesMap: map[string]*sdkSchema.Resource{
			"postgresql_database":                  resourcePostgreSQLDatabase(),
			"postgresql_default_privileges":        resourcePostgreSQLDefaultPrivileges(),
			"postgresql_extension":                 resourcePostgreSQLExtension(),
			"postgresql_grant":                     resourcePostgreSQLGrant(),
			"postgresql_grant_role":                resourcePostgreSQLGrantRole(),
			"postgresql_replication_slot":          resourcePostgreSQLReplicationSlot(),
			"postgresql_publication":               resourcePostgreSQLPublication(),
			"postgresql_subscription":              resourcePostgreSQLSubscription(),
			"postgresql_physical_replication_slot": resourcePostgreSQLPhysicalReplicationSlot(),
			// "postgresql_schema":                    resourcePostgreSQLSchema(),
			"postgresql_role":         resourcePostgreSQLRole(),
			"postgresql_function":     resourcePostgreSQLFunction(),
			"postgresql_server":       resourcePostgreSQLServer(),
			"postgresql_user_mapping": resourcePostgreSQLUserMapping(),
		},

		DataSourcesMap: map[string]*sdkSchema.Resource{
			"postgresql_schemas":   dataSourcePostgreSQLDatabaseSchemas(),
			"postgresql_tables":    dataSourcePostgreSQLDatabaseTables(),
			"postgresql_sequences": dataSourcePostgreSQLDatabaseSequences(),
		},

		ConfigureFunc: providerConfigure,
	}
}

func validateExpectedVersion(v interface{}, key string) (warnings []string, errors []error) {
	if _, err := semver.ParseTolerant(v.(string)); err != nil {
		errors = append(errors, fmt.Errorf("invalid version (%q): %w", v.(string), err))
	}
	return
}

func getRDSAuthToken(region string, profile string, username string, host string, port int64) (string, error) {
	endpoint := fmt.Sprintf("%s:%d", host, port)

	ctx := context.Background()

	var awscfg aws.Config
	var err error

	if profile != "" {
		awscfg, err = awsConfig.LoadDefaultConfig(ctx, awsConfig.WithSharedConfigProfile(profile))
	} else if region != "" {
		awscfg, err = awsConfig.LoadDefaultConfig(ctx, awsConfig.WithRegion(region))
	} else {
		awscfg, err = awsConfig.LoadDefaultConfig(ctx)
	}
	if err != nil {
		return "", err
	}

	token, err := auth.BuildAuthToken(ctx, endpoint, awscfg.Region, username, awscfg.Credentials)

	return token, err
}

func createGoogleCredsFileIfNeeded() error {
	if _, err := google.FindDefaultCredentials(context.Background()); err == nil {
		return nil
	}

	rawGoogleCredentials := os.Getenv("GOOGLE_CREDENTIALS")
	if rawGoogleCredentials == "" {
		return nil
	}

	tmpFile, err := os.CreateTemp("", "")
	if err != nil {
		return fmt.Errorf("could not create temporary file: %w", err)
	}
	defer tmpFile.Close()

	_, err = tmpFile.WriteString(rawGoogleCredentials)
	if err != nil {
		return fmt.Errorf("could not write in temporary file: %w", err)
	}

	return os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", tmpFile.Name())
}

func acquireAzureOauthToken(tenantId string) (string, error) {
	credential, err := azidentity.NewDefaultAzureCredential(
		&azidentity.DefaultAzureCredentialOptions{TenantID: tenantId})
	if err != nil {
		return "", err
	}
	token, err := credential.GetToken(context.Background(), policy.TokenRequestOptions{
		Scopes:   []string{"https://ossrdbms-aad.database.windows.net/.default"},
		TenantID: tenantId,
	})
	if err != nil {
		return "", err
	}
	return token.Token, nil
}

func convertToStringValue(d *sdkSchema.ResourceData, attrName string) types.String {
	v, ok := d.GetOk(attrName)
	if ok {
		return types.StringValue(v.(string))
	} else {
		return types.StringNull()
	}
}

func providerConfigure(d *sdkSchema.ResourceData) (interface{}, error) {
	config := PostgresProviderConfig{
		Scheme:            convertToStringValue(d, "scheme"),
		Host:              convertToStringValue(d, "host"),
		Port:              types.Int64Value(int64(d.Get("port").(int))),
		Database:          convertToStringValue(d, "database"),
		Username:          convertToStringValue(d, "username"),
		Password:          convertToStringValue(d, "password"),
		AwsRdsIamAuth:     types.BoolValue(d.Get("aws_rds_iam_auth").(bool)),
		AwsRdsIamProfile:  convertToStringValue(d, "aws_rds_iam_profile"),
		AwsRdsIamRegion:   convertToStringValue(d, "aws_rds_iam_region"),
		AzureIdentityAuth: types.BoolValue(d.Get("azure_identity_auth").(bool)),
		AzureTenantId:     convertToStringValue(d, "azure_tenant_id"),
		DatabaseUsername:  convertToStringValue(d, "database_username"),
		Superuser:         types.BoolValue(d.Get("superuser").(bool)),
		SslMode:           convertToStringValue(d, "sslmode"),
		SslRootCert:       convertToStringValue(d, "sslrootcert"),
		ConnectTimeout:    types.Int64Value(int64(d.Get("connect_timeout").(int))),
		MaxConnections:    types.Int64Value(int64(d.Get("max_connections").(int))),
		ExpectedVersion:   convertToStringValue(d, "expected_version"),
		// ClientCert: types.StringValue(d.Get("clientcert").(string)),
	}

	return getDBClient(&config)

}

func getDBClient(p *PostgresProviderConfig) (interface{}, error) {
	sslMode := GetFromAttributeOrEnv(p.SslMode, "PGSSLMODE", "")

	versionStr := defaultExpectedPostgreSQLVersion
	if !p.ExpectedVersion.IsNull() {
		versionStr = p.ExpectedVersion.ValueString()
	}

	version, _ := semver.ParseTolerant(versionStr)

	host := GetFromAttributeOrEnv(p.Host, "PGHOST", "")
	port := GetIntFromAttributeOrEnv(p.Port, "PGPORT", 5432)
	username := GetFromAttributeOrEnv(p.Username, "PGUSER", "")

	var password string
	if p.AwsRdsIamAuth.ValueBool() {
		profile := p.AwsRdsIamProfile.ValueString()
		region := p.AwsRdsIamProfile.ValueString()
		var err error
		password, err = getRDSAuthToken(region, profile, username, host, port)
		if err != nil {
			return nil, err
		}
	} else if p.AzureIdentityAuth.ValueBool() {
		tenantId := p.AzureTenantId.ValueString()
		if tenantId == "" {
			return nil, fmt.Errorf("postgresql: azure_identity_auth is enabled, azure_tenant_id must be provided also")
		}
		var err error
		password, err = acquireAzureOauthToken(tenantId)
		if err != nil {
			return nil, err
		}
	} else {
		password = GetFromAttributeOrEnv(p.Password, "PGPASSWORD", "")
	}

	scheme := "postgres"
	if !p.Scheme.IsNull() {
		scheme = p.Scheme.ValueString()
	}

	maxConns := defaultProviderMaxOpenConnections
	if !p.MaxConnections.IsNull() {
		maxConns = int(p.MaxConnections.ValueInt64())
	}

	config := Config{
		Scheme:            scheme,
		Host:              host,
		Port:              int(port),
		Username:          username,
		Password:          password,
		DatabaseUsername:  p.DatabaseUsername.ValueString(),
		Superuser:         GetBoolFromAttributeOrEnv(p.Superuser, "PGSUPERUSER", true),
		SSLMode:           sslMode,
		ApplicationName:   "Terraform provider",
		ConnectTimeoutSec: int(GetIntFromAttributeOrEnv(p.ConnectTimeout, "PGCONNECT_TIMEOUT", 180)),
		MaxConns:          maxConns,
		ExpectedVersion:   version,
		SSLRootCertPath:   p.SslRootCert.ValueString(),
	}

	// TODO
	// if value, ok := d.GetOk("clientcert"); ok {
	// 	if spec, ok := value.([]interface{})[0].(map[string]interface{}); ok {
	// 		config.SSLClientCert = &ClientCertificateConfig{
	// 			CertificatePath: spec["cert"].(string),
	// 			KeyPath:         spec["key"].(string),
	// 			SSLInline:       spec["sslinline"].(bool),
	// 		}
	// 	}
	// }

	if config.Scheme == "gcppostgres" {
		if err := createGoogleCredsFileIfNeeded(); err != nil {
			return nil, err
		}
	}

	database := GetFromAttributeOrEnv(p.Database, "PGDATABASE", "postgres")
	client := config.NewClient(database)
	return client, nil
}
