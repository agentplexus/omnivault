package omnivault

// ProviderName represents a known vault provider.
type ProviderName string

// Known provider names.
const (
	// OS-Level Credential Stores
	ProviderKeychain  ProviderName = "keychain"  // macOS Keychain
	ProviderWinCred   ProviderName = "wincred"   // Windows Credential Manager
	ProviderLibSecret ProviderName = "libsecret" // Linux Secret Service
	ProviderKeyring   ProviderName = "keyring"   // Cross-platform (auto-detect)

	// Password Managers
	Provider1Password ProviderName = "op"       // 1Password
	ProviderBitwarden ProviderName = "bw"       // Bitwarden
	ProviderLastPass  ProviderName = "lp"       // LastPass
	ProviderKeePass   ProviderName = "kp"       // KeePass/KeePassXC
	ProviderPass      ProviderName = "pass"     // pass/gopass
	ProviderDashlane  ProviderName = "dashlane" // Dashlane

	// Cloud Secret Managers
	ProviderAWSSecretsManager ProviderName = "aws-sm"   // AWS Secrets Manager
	ProviderAWSParameterStore ProviderName = "aws-ssm"  // AWS Systems Manager Parameter Store
	ProviderGCPSecretManager  ProviderName = "gcp-sm"   // Google Cloud Secret Manager
	ProviderAzureKeyVault     ProviderName = "azure-kv" // Azure Key Vault
	ProviderDigitalOcean      ProviderName = "do"       // DigitalOcean
	ProviderIBMSecretsManager ProviderName = "ibm-sm"   // IBM Cloud Secrets Manager
	ProviderOracleVault       ProviderName = "oracle"   // Oracle Cloud Vault

	// Enterprise/Self-Hosted Vaults
	ProviderHashiCorpVault ProviderName = "vault"     // HashiCorp Vault
	ProviderCyberArk       ProviderName = "conjur"    // CyberArk Conjur
	ProviderAkeyless       ProviderName = "akeyless"  // Akeyless
	ProviderInfisical      ProviderName = "infisical" // Infisical
	ProviderDoppler        ProviderName = "doppler"   // Doppler

	// Development/Local
	ProviderEnv    ProviderName = "env"    // Environment variables
	ProviderFile   ProviderName = "file"   // File-based
	ProviderMemory ProviderName = "memory" // In-memory (testing)
	ProviderDotEnv ProviderName = "dotenv" // .env files
	ProviderSOPS   ProviderName = "sops"   // Mozilla SOPS
	ProviderAge    ProviderName = "age"    // age encryption

	// Kubernetes
	ProviderK8sSecrets ProviderName = "k8s" // Kubernetes Secrets
)

// String returns the string representation of the provider name.
func (p ProviderName) String() string {
	return string(p)
}

// Scheme returns the URI scheme for this provider.
func (p ProviderName) Scheme() string {
	return string(p)
}
