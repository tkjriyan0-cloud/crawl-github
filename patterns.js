/**
 * Comprehensive list of regex patterns for sensitive data detection.
 * Categorized by service and confidence level.
 */

const PATTERNS = [
    {
        name: 'GitHub Personal Access Token',
        regex: /ghp_[a-zA-Z0-9]{36}/g,
        category: 'Source Control',
        severity: 'Critical'
    },
    {
        name: 'AWS Access Key ID',
        regex: /AKIA[0-9A-Z]{16}/g,
        category: 'Cloud',
        severity: 'High'
    },
    {
        name: 'AWS Secret Access Key',
        regex: /SECRET_ACCESS_KEY=['"]?([a-zA-Z0-9+/]{40})['"]?/gi,
        category: 'Cloud',
        severity: 'Critical'
    },
    {
        name: 'Google API Key',
        regex: /AIza[0-9A-Za-z\\-_]{35}/g,
        category: 'Cloud',
        severity: 'Medium'
    },
    {
        name: 'Slack Bot Token',
        regex: /xoxb-[0-9a-zA-Z]{10,48}/g,
        category: 'Messaging',
        severity: 'High'
    },
    {
        name: 'Slack Webhook URL',
        regex: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8}\/[a-zA-Z0-9_]{24}/g,
        category: 'Messaging',
        severity: 'Medium'
    },
    {
        name: 'Stripe Secret Key',
        regex: /sk_live_[0-9a-zA-Z]{24}/g,
        category: 'Payment',
        severity: 'Critical'
    },
    {
        name: 'Discord Bot Token',
        regex: /[MN][a-zA-Z0-9]{23}\.[a-zA-Z0-9]{6}\.[a-zA-Z0-9]{27}/g,
        category: 'Messaging',
        severity: 'High'
    },
    {
        name: 'Twilio Auth Token',
        regex: /[0-9a-f]{32}/g, // Requires context, often used with AC[0-9a-f]{32}
        category: 'Communication',
        severity: 'Medium',
        contextRegex: /AC[0-9a-f]{32}/g
    },
    {
        name: 'Generic Private Key',
        regex: /-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----/g,
        category: 'Security',
        severity: 'Critical'
    },
    {
        name: 'Firebase Config',
        regex: /apiKey: ["']AIza[0-9A-Za-z\\-_]{35}["']/g,
        category: 'Cloud',
        severity: 'Medium'
    },
    {
        name: 'Mailchimp API Key',
        regex: /[0-9a-f]{32}-us[0-9]{1,2}/g,
        category: 'Marketing',
        severity: 'Medium'
    },
    {
        name: 'Heroku API Key',
        regex: /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g,
        category: 'Cloud',
        severity: 'Critical'
    },
    {
        name: 'DigitalOcean Personal Access Token',
        regex: /dop_v1_[a-z0-9]{64}/g,
        category: 'Cloud',
        severity: 'Critical'
    },
    {
        name: 'Firebase Server Key',
        regex: /AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}/g,
        category: 'Cloud',
        severity: 'High'
    },
    {
        name: 'OpenAI API Key',
        regex: /sk-[a-zA-Z0-9]{48}/g,
        category: 'AI',
        severity: 'Critical'
    },
    {
        name: 'Anthropic API Key',
        regex: /sk-ant-sid01-[a-zA-Z0-9_-]{93}/g,
        category: 'AI',
        severity: 'Critical'
    },
    {
        name: 'Supabase Anon/Service Role Key',
        regex: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9._-]{100,}/g,
        category: 'Database',
        severity: 'High'
    },
    {
        name: 'Google Adsense Publisher ID',
        regex: /pub-[0-9]{16}/g,
        category: 'Advertising',
        severity: 'Medium'
    },
    {
        name: 'Google Adsense Client ID',
        regex: /ca-pub-[0-9]{16}/g,
        category: 'Advertising',
        severity: 'Medium'
    },
    {
        name: 'Proprietary AI Logic / Model Data',
        regex: /(INTERNAL_ONLY|PROPRIETARY|CONFIDENTIAL_DO_NOT_DISTRIBUTE|MODEL_WEIGHTS_PATH|TRAINING_DATA_LOCATION)/gi,
        category: 'Source Code',
        severity: 'Critical'
    }
];

module.exports = PATTERNS;
