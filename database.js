const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE;

class Database {
    constructor() {
        if (!supabaseUrl || !supabaseKey) {
            console.warn("Supabase credentials missing. Cloud sync disabled.");
            this.client = null;
        } else {
            this.client = createClient(supabaseUrl, supabaseKey);
        }
    }

    async saveFinding(finding) {
        if (!this.client) return null;

        try {
            const { data, error } = await this.client
                .from('leaks')
                .upsert({
                    id: `${finding.repo}-${finding.commit}-${finding.name}`.replace(/\//g, '_'),
                    name: finding.name,
                    repo: finding.repo,
                    username: finding.user,
                    severity: finding.severity,
                    url: finding.url,
                    match: finding.match,
                    context: finding.context,
                    full_match: finding.full_match,
                    user_intel: finding.user_intel,
                    local_path: finding.local_path,
                    timestamp: finding.timestamp
                });

            if (error) throw error;
            return data;
        } catch (error) {
            console.error("Supabase Save Error:", error.message);
            return null;
        }
    }

    async getAllFindings() {
        if (!this.client) return [];
        try {
            const { data, error } = await this.client
                .from('leaks')
                .select('*')
                .order('timestamp', { ascending: false });
            
            if (error) throw error;
            return data;
        } catch (error) {
            console.error("Supabase Fetch Error:", error.message);
            return [];
        }
    }
}

module.exports = new Database();
