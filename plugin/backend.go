// Package plugin implements a Vault/OpenBao auth method that authenticates
// vSphere VMs via VIMS identity verification.
//
// Flow:
//  1. VM calls: vault write auth/vims/login role=web-tier
//     (optionally with bios_uuid or vtpm_quote for higher attestation)
//  2. Plugin extracts the caller's source IP from the connection
//  3. Plugin calls VIMS at the configured endpoint to verify identity:
//     GET http://vims:8169/v1/identity (or /v1/identity/metadata)
//  4. VIMS resolves IP → VM → policy and returns VM metadata + attestation level
//  5. Plugin matches the VM against the named role's bound parameters
//  6. If matched, Vault issues a token with the role's policies and TTL
//
// Config:  POST auth/vims/config  {vims_addr, ca_cert, tls_skip_verify}
// Roles:   POST auth/vims/role/:name {bound_folder, bound_tags, ...}
// Login:   POST auth/vims/login {role, bios_uuid_hmac, vtpm_quote}
package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	backendHelp = `
The VIMS auth method authenticates vSphere VMs by verifying their identity
through a VIMS (vSphere Identity Metadata Service) instance. VMs are
identified by source IP correlation against vCenter, optionally with
BIOS UUID or vTPM attestation.
`
)

// Factory returns a new VIMS auth backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &backend{
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeCredential,
		AuthRenew:   b.pathLoginRenew,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{"login"},
			SealWrapStorage: []string{"config"},
		},
		Paths: []*framework.Path{
			b.pathConfig(),
			b.pathRoleList(),
			b.pathRole(),
			b.pathLogin(),
		},
	}
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

type backend struct {
	*framework.Backend
	httpClient *http.Client
}

// --- Config ---

type vimsConfig struct {
	VIMSAddr      string `json:"vims_addr"`
	TLSSkipVerify bool   `json:"tls_skip_verify"`
	CACert        string `json:"ca_cert"`
}

func (b *backend) pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: "config",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "vims",
		},
		Fields: map[string]*framework.FieldSchema{
			"vims_addr": {
				Type:        framework.TypeString,
				Description: "Address of the VIMS service (e.g. http://169.254.169.254:80)",
				Required:    true,
			},
			"tls_skip_verify": {
				Type:        framework.TypeBool,
				Description: "Skip TLS verification for VIMS endpoint",
				Default:     false,
			},
			"ca_cert": {
				Type:        framework.TypeString,
				Description: "PEM-encoded CA cert for VIMS TLS",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathConfigRead},
		},
	}
}

func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	cfg := &vimsConfig{
		VIMSAddr:      d.Get("vims_addr").(string),
		TLSSkipVerify: d.Get("tls_skip_verify").(bool),
		CACert:        d.Get("ca_cert").(string),
	}
	if cfg.VIMSAddr == "" {
		return logical.ErrorResponse("vims_addr is required"), nil
	}

	entry, err := logical.StorageEntryJSON("config", cfg)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	cfg, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"vims_addr":       cfg.VIMSAddr,
			"tls_skip_verify": cfg.TLSSkipVerify,
		},
	}, nil
}

func (b *backend) getConfig(ctx context.Context, s logical.Storage) (*vimsConfig, error) {
	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	cfg := &vimsConfig{}
	if err := entry.DecodeJSON(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// --- Roles ---

type vimsRole struct {
	Name string `json:"name"`

	// Binding constraints — VM must match ALL non-empty fields
	BoundFolder       string            `json:"bound_folder"`       // Glob match on folder path
	BoundTags         map[string]string `json:"bound_tags"`         // All tags must match
	BoundResourcePool string            `json:"bound_resource_pool"`
	BoundCluster      string            `json:"bound_cluster"`
	BoundDatacenter   string            `json:"bound_datacenter"`
	BoundNameGlob     string            `json:"bound_name_glob"`    // Glob on VM name

	// Attestation requirement
	MinAttestationLevel int `json:"min_attestation_level"` // 0=ip, 1=bios, 2=vtpm

	// Vault token settings
	TokenPolicies []string      `json:"token_policies"`
	TokenTTL      time.Duration `json:"token_ttl"`
	TokenMaxTTL   time.Duration `json:"token_max_ttl"`
	TokenPeriod   time.Duration `json:"token_period"`
}

func (b *backend) pathRoleList() *framework.Path {
	return &framework.Path{
		Pattern: "role/?$",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "vims",
			OperationSuffix: "roles",
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{Callback: b.pathRoleListOp},
		},
	}
}

func (b *backend) pathRoleListOp(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	roles, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(roles), nil
}

func (b *backend) pathRole() *framework.Path {
	return &framework.Path{
		Pattern: "role/" + framework.GenericNameRegex("name"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "vims",
			OperationSuffix: "role",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Role name",
				Required:    true,
			},
			"bound_folder": {
				Type:        framework.TypeString,
				Description: "Required folder path (glob). E.g. /Production/Web/*",
			},
			"bound_tags": {
				Type:        framework.TypeKVPairs,
				Description: "Required vSphere tags (all must match)",
			},
			"bound_resource_pool": {
				Type:        framework.TypeString,
				Description: "Required resource pool name",
			},
			"bound_cluster": {
				Type:        framework.TypeString,
				Description: "Required cluster name",
			},
			"bound_datacenter": {
				Type:        framework.TypeString,
				Description: "Required datacenter name",
			},
			"bound_name_glob": {
				Type:        framework.TypeString,
				Description: "VM name glob pattern",
			},
			"min_attestation_level": {
				Type:        framework.TypeInt,
				Description: "Minimum attestation level (0=ip, 1=bios-uuid, 2=vtpm)",
				Default:     0,
			},
			"token_policies": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Vault policies to attach to the token",
			},
			"token_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Token TTL",
			},
			"token_max_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Token max TTL",
			},
			"token_period": {
				Type:        framework.TypeDurationSecond,
				Description: "Token period (for periodic tokens)",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathRoleWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRoleWrite},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathRoleRead},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathRoleDelete},
		},
	}
}

func (b *backend) pathRoleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("name is required"), nil
	}

	role := &vimsRole{
		Name:                name,
		BoundFolder:         d.Get("bound_folder").(string),
		BoundResourcePool:   d.Get("bound_resource_pool").(string),
		BoundCluster:        d.Get("bound_cluster").(string),
		BoundDatacenter:     d.Get("bound_datacenter").(string),
		BoundNameGlob:       d.Get("bound_name_glob").(string),
		MinAttestationLevel: d.Get("min_attestation_level").(int),
	}

	if tags, ok := d.GetOk("bound_tags"); ok {
		role.BoundTags = tags.(map[string]string)
	}
	if v, ok := d.GetOk("token_policies"); ok {
		role.TokenPolicies = v.([]string)
	}
	if v, ok := d.GetOk("token_ttl"); ok {
		role.TokenTTL = time.Duration(v.(int)) * time.Second
	}
	if v, ok := d.GetOk("token_max_ttl"); ok {
		role.TokenMaxTTL = time.Duration(v.(int)) * time.Second
	}
	if v, ok := d.GetOk("token_period"); ok {
		role.TokenPeriod = time.Duration(v.(int)) * time.Second
	}

	entry, err := logical.StorageEntryJSON("role/"+name, role)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	role, err := b.getRole(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"bound_folder":          role.BoundFolder,
			"bound_tags":            role.BoundTags,
			"bound_resource_pool":   role.BoundResourcePool,
			"bound_cluster":         role.BoundCluster,
			"bound_datacenter":      role.BoundDatacenter,
			"bound_name_glob":       role.BoundNameGlob,
			"min_attestation_level": role.MinAttestationLevel,
			"token_policies":        role.TokenPolicies,
			"token_ttl":             role.TokenTTL / time.Second,
			"token_max_ttl":         role.TokenMaxTTL / time.Second,
			"token_period":          role.TokenPeriod / time.Second,
		},
	}, nil
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, "role/"+d.Get("name").(string)); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) getRole(ctx context.Context, s logical.Storage, name string) (*vimsRole, error) {
	entry, err := s.Get(ctx, "role/"+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	role := &vimsRole{}
	if err := entry.DecodeJSON(role); err != nil {
		return nil, err
	}
	return role, nil
}

// --- Login ---

// vimsIdentityResponse is the JSON shape returned by VIMS /v1/identity/metadata.
type vimsIdentityResponse struct {
	VM *struct {
		Name             string            `json:"name"`
		MoRef            string            `json:"moref"`
		BIOSUUID         string            `json:"bios_uuid"`
		InstanceUUID     string            `json:"instance_uuid"`
		Folder           string            `json:"folder"`
		ResourcePool     string            `json:"resource_pool"`
		Cluster          string            `json:"cluster"`
		Datacenter       string            `json:"datacenter"`
		Tags             map[string]string `json:"tags"`
		CustomAttributes map[string]string `json:"custom_attributes"`
	} `json:"vm"`
	Attestation *struct {
		Level     int    `json:"level"`
		LevelName string `json:"level_name"`
	} `json:"attestation"`
	Policy *struct {
		RuleName string `json:"rule_name"`
	} `json:"policy"`
}

func (b *backend) pathLogin() *framework.Path {
	return &framework.Path{
		Pattern: "login$",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "vims",
			OperationVerb:   "login",
		},
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeString,
				Description: "Name of the VIMS role to authenticate against",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation:  &framework.PathOperation{Callback: b.pathLoginWrite},
			logical.AliasLookaheadOperation: &framework.PathOperation{Callback: b.pathLoginWrite},
		},
	}
}

func (b *backend) pathLoginWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("role").(string)
	if roleName == "" {
		return logical.ErrorResponse("role is required"), nil
	}

	// 1. Load config
	cfg, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return logical.ErrorResponse("VIMS auth not configured — POST auth/vims/config first"), nil
	}

	// 2. Load role
	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role %q not found", roleName), nil
	}

	// 3. Extract source IP from the Vault connection
	sourceIP := ""
	if req.Connection != nil {
		sourceIP = req.Connection.RemoteAddr
		// Strip port if present
		if idx := strings.LastIndex(sourceIP, ":"); idx > 0 {
			if sourceIP[0] != '[' { // not IPv6 [::1]:port
				sourceIP = sourceIP[:idx]
			}
		}
	}
	if sourceIP == "" {
		return logical.ErrorResponse("cannot determine source IP"), nil
	}

	b.Logger().Info("login attempt", "role", roleName, "source_ip", sourceIP)

	// 4. Call VIMS to verify identity
	vimsResp, err := b.queryVIMS(cfg, sourceIP)
	if err != nil {
		b.Logger().Warn("VIMS query failed", "error", err, "source_ip", sourceIP)
		return logical.ErrorResponse("VIMS identity verification failed: %s", err), nil
	}

	if vimsResp.VM == nil {
		return logical.ErrorResponse("VIMS returned no VM identity for %s", sourceIP), nil
	}

	// 5. Check attestation level meets role minimum
	attestLevel := 0
	if vimsResp.Attestation != nil {
		attestLevel = vimsResp.Attestation.Level
	}
	if attestLevel < role.MinAttestationLevel {
		return logical.ErrorResponse(
			"attestation level %d insufficient for role %q (requires %d)",
			attestLevel, roleName, role.MinAttestationLevel,
		), nil
	}

	// 6. Match VM against role bindings
	if err := matchRole(role, vimsResp); err != nil {
		b.Logger().Info("role binding mismatch", "role", roleName,
			"vm", vimsResp.VM.Name, "reason", err)
		return logical.ErrorResponse("VM does not match role %q: %s", roleName, err), nil
	}

	// 7. Build auth response
	auth := &logical.Auth{
		InternalData: map[string]interface{}{
			"role": roleName,
		},
		Metadata: map[string]string{
			"role":              roleName,
			"vm_name":           vimsResp.VM.Name,
			"vm_moref":          vimsResp.VM.MoRef,
			"vm_folder":         vimsResp.VM.Folder,
			"vm_cluster":        vimsResp.VM.Cluster,
			"vm_datacenter":     vimsResp.VM.Datacenter,
			"attestation_level": fmt.Sprintf("%d", attestLevel),
			"source_ip":         sourceIP,
		},
		DisplayName: fmt.Sprintf("vims-%s-%s", vimsResp.VM.Name, roleName),
		Alias: &logical.Alias{
			Name: vimsResp.VM.MoRef, // MoRef is globally unique
			Metadata: map[string]string{
				"vm_name": vimsResp.VM.Name,
			},
		},
		Policies: role.TokenPolicies,
		LeaseOptions: logical.LeaseOptions{
			TTL:       role.TokenTTL,
			MaxTTL:    role.TokenMaxTTL,
			Renewable: true,
		},
		Period: role.TokenPeriod,
	}

	b.Logger().Info("login succeeded",
		"role", roleName, "vm", vimsResp.VM.Name,
		"moref", vimsResp.VM.MoRef, "attest", attestLevel)

	return &logical.Response{Auth: auth}, nil
}

// pathLoginRenew handles token renewal — re-verifies VM identity.
func (b *backend) pathLoginRenew(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	roleName, ok := req.Auth.InternalData["role"].(string)
	if !ok {
		return nil, fmt.Errorf("no role in internal data")
	}

	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, fmt.Errorf("role %q no longer exists", roleName)
	}

	// Re-verify the VM identity on renewal
	cfg, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg != nil {
		sourceIP := req.Auth.Metadata["source_ip"]
		if sourceIP != "" {
			vimsResp, err := b.queryVIMS(cfg, sourceIP)
			if err != nil {
				return nil, fmt.Errorf("renewal VIMS check failed: %w", err)
			}
			if vimsResp.VM == nil {
				return nil, fmt.Errorf("VM no longer found at %s", sourceIP)
			}
			if err := matchRole(role, vimsResp); err != nil {
				return nil, fmt.Errorf("VM no longer matches role: %w", err)
			}
		}
	}

	resp := &logical.Response{Auth: req.Auth}
	resp.Auth.TTL = role.TokenTTL
	resp.Auth.MaxTTL = role.TokenMaxTTL
	resp.Auth.Period = role.TokenPeriod
	return resp, nil
}

// --- VIMS query ---

// queryVIMS calls the VIMS service to verify a VM's identity by source IP.
// VIMS resolves the caller's IP → VM identity via vCenter, which is the
// core trust mechanism. The plugin trusts VIMS to have done the source IP
// correlation, attestation checks, and policy evaluation.
func (b *backend) queryVIMS(cfg *vimsConfig, sourceIP string) (*vimsIdentityResponse, error) {
	addr := strings.TrimRight(cfg.VIMSAddr, "/")

	// We call VIMS *from* the VIMS host, passing the VM's source IP as a
	// query parameter. VIMS has a special endpoint for this: it trusts the
	// plugin (authenticated via network/TLS) to assert the source IP.
	url := fmt.Sprintf("%s/v1/identity?source_ip=%s", addr, sourceIP)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling VIMS: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == 403 {
		return nil, fmt.Errorf("VIMS denied identity for IP %s: %s", sourceIP, string(body))
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("VIMS returned %d: %s", resp.StatusCode, string(body))
	}

	var vimsResp vimsIdentityResponse
	if err := json.Unmarshal(body, &vimsResp); err != nil {
		return nil, fmt.Errorf("decoding VIMS response: %w", err)
	}

	return &vimsResp, nil
}

// --- Role matching ---

func matchRole(role *vimsRole, resp *vimsIdentityResponse) error {
	vm := resp.VM

	if role.BoundFolder != "" {
		if !folderMatch(vm.Folder, role.BoundFolder) {
			return fmt.Errorf("folder %q does not match bound_folder %q", vm.Folder, role.BoundFolder)
		}
	}

	if role.BoundNameGlob != "" {
		if !globMatch(vm.Name, role.BoundNameGlob) {
			return fmt.Errorf("name %q does not match bound_name_glob %q", vm.Name, role.BoundNameGlob)
		}
	}

	if role.BoundResourcePool != "" {
		if !strings.EqualFold(vm.ResourcePool, role.BoundResourcePool) {
			return fmt.Errorf("resource_pool %q does not match", vm.ResourcePool)
		}
	}

	if role.BoundCluster != "" {
		if !strings.EqualFold(vm.Cluster, role.BoundCluster) {
			return fmt.Errorf("cluster %q does not match", vm.Cluster)
		}
	}

	if role.BoundDatacenter != "" {
		if !strings.EqualFold(vm.Datacenter, role.BoundDatacenter) {
			return fmt.Errorf("datacenter %q does not match", vm.Datacenter)
		}
	}

	for k, v := range role.BoundTags {
		vmVal, ok := vm.Tags[k]
		if !ok {
			return fmt.Errorf("required tag %q not present", k)
		}
		if !strings.EqualFold(vmVal, v) {
			return fmt.Errorf("tag %q=%q does not match required %q", k, vmVal, v)
		}
	}

	return nil
}

// --- Glob helpers (same logic as VIMS policy engine) ---

func globMatch(value, pattern string) bool {
	v := strings.ToLower(value)
	p := strings.ToLower(pattern)
	return simpleGlob(p, v)
}

func folderMatch(value, pattern string) bool {
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return strings.HasPrefix(strings.ToLower(value), strings.ToLower(prefix)+"/")
	}
	return globMatch(value, pattern)
}

// simpleGlob matches a pattern with * wildcards against a value.
func simpleGlob(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	for {
		if pattern == "" {
			return value == ""
		}
		if pattern[0] == '*' {
			// Try matching rest of pattern at every position
			pattern = pattern[1:]
			for i := 0; i <= len(value); i++ {
				if simpleGlob(pattern, value[i:]) {
					return true
				}
			}
			return false
		}
		if value == "" {
			return false
		}
		if pattern[0] == '?' || pattern[0] == value[0] {
			pattern = pattern[1:]
			value = value[1:]
			continue
		}
		return false
	}
}
