package main

// Generated from the upstream Pinkerton rules. DO NOT EDIT.
//
// Source: github.com/000pp/Pinkerton, src/pinkerton/modules/secret.py
// Upstream commit: 6deb355
//
// The rule text is the original's, wrapped so that capture group 1 holds the
// secret itself. Several upstream patterns have no capturing group at all
// (`(?:ghu|ghs)_[0-9a-zA-Z]{36}`), and reading group 1 from them yields an
// empty value: the rule would match and report nothing. The wrapper is what
// makes those rules answer at all.

import "regexp"

// pinkertonRules is the upstream secret list, ported as it is.
//
// The ids are ours, not upstream's: upstream keys findings by a human label
// ("Amazon AWS Access Key ID") while this project's findings are keyed by a
// stable id that travels into PostgreSQL and into every export, so the label
// would become an identifier. The label is kept as the severity text, which is
// what an operator reads.
var pinkertonRules = []secretRule{
	{
		id:       "pinkerton_amazon_aws_access_key_id",
		pattern:  regexp.MustCompile("(AKIA[0-9A-Z]{16})"),
		severity: "Amazon AWS Access Key ID",
	},
	{
		id:       "pinkerton_amazon_mws_auth_token",
		pattern:  regexp.MustCompile(`(amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`),
		severity: "Amazon MWS Auth Token",
	},
	{
		id:       "pinkerton_amazon_aws_s3_url",
		pattern:  regexp.MustCompile(`(s3\.amazonaws\.com/+|[a-zA-Z0-9_\-]+\.s3\.amazonaws\.com)`),
		severity: "Amazon AWS S3 URL",
	},
	{
		id:       "pinkerton_google_api_key",
		pattern:  regexp.MustCompile(`(AIza[0-9A-Za-z\-_]{35})`),
		severity: "Google API Key",
	},
	{
		id:       "pinkerton_google_oauth_access_token",
		pattern:  regexp.MustCompile(`(ya29\.[0-9A-Za-z\-_]+)`),
		severity: "Google OAuth Access Token",
	},
	{
		id:       "pinkerton_google_cloud_platform_oauth",
		pattern:  regexp.MustCompile(`([0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)`),
		severity: "Google Cloud Platform OAuth",
	},
	{
		id:       "pinkerton_google_gcp_service_account",
		pattern:  regexp.MustCompile("(\"type\"\\s*:\\s*\"service_account\")"),
		severity: "Google GCP Service Account",
	},
	{
		id:       "pinkerton_google_captcha_key",
		pattern:  regexp.MustCompile(`(6L[0-9A-Za-z\-_]{38})`),
		severity: "Google Captcha Key",
	},
	{
		id:       "pinkerton_firebase_key",
		pattern:  regexp.MustCompile(`(AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140})`),
		severity: "Firebase Key",
	},
	{
		id:       "pinkerton_firebase_url",
		pattern:  regexp.MustCompile(`([a-zA-Z0-9\-]+\.firebaseio\.com)`),
		severity: "Firebase URL",
	},
	{
		id:       "pinkerton_github_personal_access_token",
		pattern:  regexp.MustCompile("(ghp_[0-9a-zA-Z]{36})"),
		severity: "GitHub Personal Access Token",
	},
	{
		id:       "pinkerton_github_app_token",
		pattern:  regexp.MustCompile("((?:ghu|ghs)_[0-9a-zA-Z]{36})"),
		severity: "GitHub App Token",
	},
	{
		id:       "pinkerton_github_access_token",
		pattern:  regexp.MustCompile(`([a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-]+@github\.com)`),
		severity: "GitHub Access Token",
	},
	{
		id:       "pinkerton_github_url",
		pattern:  regexp.MustCompile("((?i)github.*['\\\"][0-9a-zA-Z]{35,40}['\\\"])"),
		severity: "GitHub URL",
	},
	{
		id:       "pinkerton_gitlab_personal_access_token",
		pattern:  regexp.MustCompile(`(glpat-[0-9a-zA-Z\-_]{20})`),
		severity: "GitLab Personal Access Token",
	},
	{
		id:       "pinkerton_slack_token",
		pattern:  regexp.MustCompile("(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})"),
		severity: "Slack Token",
	},
	{
		id:       "pinkerton_slack_webhook",
		pattern:  regexp.MustCompile(`(https://hooks\.slack\.com/services/T\w{8}/B\w{8}/\w{24})`),
		severity: "Slack Webhook",
	},
	{
		id:       "pinkerton_slack_webhook_short",
		pattern:  regexp.MustCompile("(T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24})"),
		severity: "Slack Webhook Short",
	},
	{
		id:       "pinkerton_slack_oauth_v2_bot_token",
		pattern:  regexp.MustCompile("(xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24})"),
		severity: "Slack OAuth v2 Bot Token",
	},
	{
		id:       "pinkerton_slack_oauth_v2_config_token",
		pattern:  regexp.MustCompile(`(xoxe\.xoxp-1-[0-9a-zA-Z]{166})`),
		severity: "Slack OAuth v2 Config Token",
	},
	{
		id:       "pinkerton_stripe_api_key",
		pattern:  regexp.MustCompile("(sk_live_[0-9a-zA-Z]{24})"),
		severity: "Stripe API Key",
	},
	{
		id:       "pinkerton_stripe_restricted_api_key",
		pattern:  regexp.MustCompile("(rk_live_[0-9a-zA-Z]{24})"),
		severity: "Stripe Restricted API Key",
	},
	{
		id:       "pinkerton_shopify_private_app_access_token",
		pattern:  regexp.MustCompile("(shppa_[a-fA-F0-9]{32})"),
		severity: "Shopify Private App Access Token",
	},
	{
		id:       "pinkerton_shopify_shared_secret",
		pattern:  regexp.MustCompile("(shpss_[a-fA-F0-9]{32})"),
		severity: "Shopify Shared Secret",
	},
	{
		id:       "pinkerton_shopify_custom_access_token",
		pattern:  regexp.MustCompile("(shpca_[a-fA-F0-9]{32})"),
		severity: "Shopify Custom Access Token",
	},
	{
		id:       "pinkerton_shopify_access_token",
		pattern:  regexp.MustCompile("(shpat_[a-fA-F0-9]{32})"),
		severity: "Shopify Access Token",
	},
	{
		id:       "pinkerton_twitter_access_token",
		pattern:  regexp.MustCompile(`((?i)twitter.*[1-9][0-9]+-\w{40})`),
		severity: "Twitter Access Token",
	},
	{
		id:       "pinkerton_twitter_oauth",
		pattern:  regexp.MustCompile("((?i)twitter.*['\\\"][a-zA-Z0-9_]{35,44}['\\\"])"),
		severity: "Twitter OAuth",
	},
	{
		id:       "pinkerton_twitter_client_id",
		pattern:  regexp.MustCompile("((?i)twitter(?:.{0,20})?['\\\"][0-9a-z]{18,25})"),
		severity: "Twitter Client ID",
	},
	{
		id:       "pinkerton_facebook_access_token",
		pattern:  regexp.MustCompile("(EAACEdEose0cBA[0-9A-Za-z]+)"),
		severity: "Facebook Access Token",
	},
	{
		id:       "pinkerton_facebook_oauth",
		pattern:  regexp.MustCompile("((?i)facebook.*['\\\"][0-9a-f]{32}['\\\"])"),
		severity: "Facebook OAuth",
	},
	{
		id:       "pinkerton_facebook_client_id",
		pattern:  regexp.MustCompile("((?i)(?:facebook|fb)(?:.{0,20})?['\\\"][0-9]{13,17})"),
		severity: "Facebook Client ID",
	},
	{
		id:       "pinkerton_linkedin_secret_key",
		pattern:  regexp.MustCompile("((?i)linkedin(?:.{0,20})?['\\\"][0-9a-z]{16}['\\\"])"),
		severity: "LinkedIn Secret Key",
	},
	{
		id:       "pinkerton_artifactory_api_token",
		pattern:  regexp.MustCompile("((?:\\s|=|:|\"|^)AKC[a-zA-Z0-9]{10,})"),
		severity: "Artifactory API Token",
		// Both Artifactory rules take the digit requirement. They came from
		// Pinkerton, which scans Git commits where a JavaScript property named
		// `AP…` is rare; against a minified bundle their classes admit every
		// such property. Measured on `yandex.ru/ads/system/context.js`, 433 340
		// bytes: `{key:"APExcludedBlocks"}` and `{key:"APExceptionBlocks"}` are
		// the only two `AP*` identifiers in the file, neither carries a digit,
		// and `APExcludedBlocks` was reported to the operator as a leaked
		// password. A JFrog reference token is 73 characters of base62, so this
		// cannot cost a real one.
		digitRequired: true,
	},
	{
		id:       "pinkerton_artifactory_password",
		pattern:  regexp.MustCompile("((?:\\s|=|:|\"|^)AP[\\dABCDEF][a-zA-Z0-9]{8,})"),
		severity: "Artifactory Password",
		// See the rule above: same defect, same measurement, same gate.
		digitRequired: true,
	},
	{
		id:       "pinkerton_paypal_braintree_access_token",
		pattern:  regexp.MustCompile(`(access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})`),
		severity: "PayPal Braintree Access Token",
	},
	{
		id:       "pinkerton_square_access_token",
		pattern:  regexp.MustCompile(`(sq0atp-[0-9A-Za-z\-_]{22})`),
		severity: "Square Access Token",
	},
	{
		id:       "pinkerton_square_oauth_secret",
		pattern:  regexp.MustCompile(`(sq0csp-[0-9A-Za-z\-_]{43})`),
		severity: "Square OAuth Secret",
	},
	{
		id:       "pinkerton_cloudinary_basic_auth",
		pattern:  regexp.MustCompile("(cloudinary://[0-9]{15}:[0-9A-Za-z]+@[a-z]+)"),
		severity: "Cloudinary Basic Auth",
	},
	{
		id:       "pinkerton_picatic_api_key",
		pattern:  regexp.MustCompile("(sk_live_[0-9a-z]{32})"),
		severity: "Picatic API Key",
	},
	{
		id:       "pinkerton_adobe_client_secret",
		pattern:  regexp.MustCompile(`((?i)\bp8e-[a-zA-Z0-9]{32})`),
		severity: "Adobe Client Secret",
	},
	{
		id:       "pinkerton_alibaba_accesskey_id",
		pattern:  regexp.MustCompile(`(\bLTAI[a-zA-Z0-9]{20}\b)`),
		severity: "Alibaba AccessKey ID",
	},
	{
		id:       "pinkerton_clojars_api_token",
		pattern:  regexp.MustCompile("((?i)CLOJARS_[a-z0-9]{60})"),
		severity: "Clojars API Token",
	},
	{
		id:       "pinkerton_doppler_api_token",
		pattern:  regexp.MustCompile(`(dp\.pt\.[a-zA-Z0-9]{43})`),
		severity: "Doppler API Token",
	},
	{
		id:       "pinkerton_dynatrace_api_token",
		pattern:  regexp.MustCompile(`(dt0c01\.[a-zA-Z0-9]{24}\.[a-z0-9]{64})`),
		severity: "Dynatrace API Token",
	},
	{
		id:       "pinkerton_easypost_api_token",
		pattern:  regexp.MustCompile("(EZAK[a-zA-Z0-9]{54})"),
		severity: "EasyPost API Token",
	},
	{
		id:       "pinkerton_npm_access_token",
		pattern:  regexp.MustCompile(`(\bnpm_[a-z0-9]{36}\b)`),
		severity: "NPM Access Token",
	},
	{
		id:       "pinkerton_mailgun_api_key",
		pattern:  regexp.MustCompile("(key-[0-9a-zA-Z]{32})"),
		severity: "Mailgun API Key",
	},
	{
		id:       "pinkerton_mailchimp_api_key",
		pattern:  regexp.MustCompile("([0-9a-f]{32}-us[0-9]{1,2})"),
		severity: "MailChimp API Key",
	},
	{
		id:       "pinkerton_twilio_api_key",
		pattern:  regexp.MustCompile("(SK[0-9a-fA-F]{32})"),
		severity: "Twilio API Key",
	},
	{
		id:       "pinkerton_asana_client_id",
		pattern:  regexp.MustCompile("((?i)asana[0-9a-z\\-_\\t .]{0,20}[\\s'\\\"]{0,3}(?:=|>|:=|\\|\\|:|<=|=>|:)['\\\"\\s=`]{0,5}([0-9]{16})['\\\"\\n\\r\\s`;])"),
		severity: "Asana Client ID",
	},
	{
		id:       "pinkerton_asana_client_secret",
		pattern:  regexp.MustCompile("((?i)asana[0-9a-z\\-_\\t .]{0,20}[\\s'\\\"]{0,3}(?:=|>|:=|\\|\\|:|<=|=>|:)['\\\"\\s=`]{0,5}([a-z0-9]{32})['\\\"\\n\\r\\s`;])"),
		severity: "Asana Client Secret",
	},
	{
		id:       "pinkerton_authorization_bearer",
		pattern:  regexp.MustCompile(`([Bb]earer [a-zA-Z0-9_\-\.=]+)`),
		severity: "Authorization Bearer",
	},
	{
		id:       "pinkerton_authorization_basic",
		pattern:  regexp.MustCompile(`([Bb]asic [a-zA-Z0-9=:_\+/\-]{5,100})`),
		severity: "Authorization Basic",
	},
	{
		id:       "pinkerton_jwt_token",
		pattern:  regexp.MustCompile(`(eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]+)`),
		severity: "JWT Token",
	},
	{
		id:       "pinkerton_pgp_private_key_block",
		pattern:  regexp.MustCompile("(-----BEGIN PGP PRIVATE KEY BLOCK-----)"),
		severity: "PGP Private Key Block",
	},
	{
		id:       "pinkerton_ssh_dsa_private_key",
		pattern:  regexp.MustCompile("(-----BEGIN DSA PRIVATE KEY-----)"),
		severity: "SSH DSA Private Key",
	},
	{
		id:       "pinkerton_ssh_ec_private_key",
		pattern:  regexp.MustCompile("(-----BEGIN EC PRIVATE KEY-----)"),
		severity: "SSH EC Private Key",
	},
	{
		id:       "pinkerton_ssh_openssh_private_key",
		pattern:  regexp.MustCompile("(-----BEGIN OPENSSH PRIVATE KEY-----)"),
		severity: "SSH OpenSSH Private Key",
	},
	{
		id:       "pinkerton_rsa_private_key",
		pattern:  regexp.MustCompile("(-----BEGIN RSA PRIVATE KEY-----)"),
		severity: "RSA Private Key",
	},
	{
		id:       "pinkerton_ssh_ed25519_public_key",
		pattern:  regexp.MustCompile("(ssh-ed25519)"),
		severity: "SSH ed25519 Public Key",
	},
	{
		id:       "pinkerton_generic_api_key",
		pattern:  regexp.MustCompile("((?i)api[_]?key\\s*[:=]\\s*['\\\"]([a-zA-Z0-9_\\-]{32,45})['\\\"])"),
		severity: "Generic API Key",
	},
	{
		id:       "pinkerton_generic_secret",
		pattern:  regexp.MustCompile("((?i)secret\\s*[:=]\\s*['\\\"]([a-zA-Z0-9_\\-]{32,45})['\\\"])"),
		severity: "Generic Secret",
	},
	{
		id:       "pinkerton_mailto",
		pattern:  regexp.MustCompile(`(mailto:[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z0-9.\-]+)`),
		severity: "Mailto",
	},
}
