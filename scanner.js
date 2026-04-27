const { Octokit } = require("octokit");
const axios = require("axios");
const chalk = require("chalk");
const fs = require("fs");
const path = require("path");
const PATTERNS = require("./patterns");
const userIntel = require("./osint");
const downloader = require("./downloader");
const db = require("./database");
const { DateTime } = require("luxon");
require("dotenv").config();

class GitHubScanner {
    constructor() {
        this.token = process.env.GITHUB_TOKEN;
        if (!this.token) {
            console.warn(chalk.yellow("Warning: GITHUB_TOKEN not found in .env. Running with extreme rate limits."));
        }
        this.octokit = new Octokit({ auth: this.token });
        this.storagePath = path.join(__dirname, "storage.json");
        this.storage = JSON.parse(fs.readFileSync(this.storagePath, "utf8"));
        this.isScanning = false;
        this.rateLimit = { limit: 5000, remaining: 5000, reset: null };
        
        // Safety Config
        this.minSleep = 60000; // 1 minute
        this.maxSleep = 120000; // 2 minutes
        this.backoffMultiplier = 1;
    }

    async saveStorage() {
        fs.writeFileSync(this.storagePath, JSON.stringify(this.storage, null, 4));
    }

    async logFinding(finding) {
        console.log(chalk.red.bold(`\n[!] LEAK DETECTED: ${finding.name}`));
        console.log(chalk.white(`    Repo: ${finding.repo}`));
        console.log(chalk.white(`    User: ${finding.user}`));
        console.log(chalk.blue(`    URL: ${finding.url}\n`));

        const findingWithTime = {
            ...finding,
            timestamp: DateTime.now().toISO()
        };

        this.storage.findings.push(findingWithTime);
        this.storage.stats.total_leaks_found++;
        
        // Sync to Supabase Cloud
        await db.saveFinding(findingWithTime);
        
        await this.saveStorage();
    }

    async analyzeDiff(repoName, commitSha, commitUrl) {
        try {
            const response = await axios.get(`${commitUrl}.diff`, {
                headers: this.token ? { Authorization: `token ${this.token}` } : {}
            });
            
            // Update rate limit from headers if available
            if (response.headers['x-ratelimit-remaining']) {
                this.rateLimit.remaining = parseInt(response.headers['x-ratelimit-remaining']);
                this.rateLimit.reset = parseInt(response.headers['x-ratelimit-reset']);
            }

            const diffContent = response.data;
            this.storage.stats.total_scanned_commits++;

            for (const pattern of PATTERNS) {
                const matches = diffContent.match(pattern.regex);
                if (matches) {
                    for (const match of matches) {
                        const isDuplicate = this.storage.findings.some(f => f.commit === commitSha && f.name === pattern.name);
                        if (!isDuplicate) {
                            // Extract context (lines around the match)
                            const lines = diffContent.split('\n');
                            const matchLineIndex = lines.findIndex(l => l.includes(match));
                            const context = lines.slice(Math.max(0, matchLineIndex - 2), Math.min(lines.length, matchLineIndex + 3)).join('\n');

                            const intel = await userIntel.enrich(repoName.split('/')[0]);
                            
                            let downloadedPath = null;
                            if (pattern.severity === 'Critical') {
                                // Attempt to download the raw file
                                const rawUrl = commitUrl.replace("github.com", "raw.githubusercontent.com").replace("/commit/", "/");
                                downloadedPath = await downloader.download(rawUrl, `${pattern.name.replace(/ /g, '_')}_${commitSha.substring(0,7)}.txt`, repoName);
                            }

                            await this.logFinding({
                                name: pattern.name,
                                repo: repoName,
                                user: repoName.split('/')[0],
                                commit: commitSha,
                                url: commitUrl,
                                severity: pattern.severity,
                                match: match.substring(0, 10) + "...",
                                context: context,
                                full_match: match,
                                user_intel: intel,
                                local_path: downloadedPath
                            });
                        }
                    }
                }
            }
        } catch (error) {
            if (error.response && (error.response.status === 403 || error.response.status === 429)) {
                this.backoffMultiplier++;
                console.log(chalk.red(`\n[!] Safety Triggered: Rate limit hit. Backing off (Level ${this.backoffMultiplier})...`));
            }
        }
    }

    async waitSafety() {
        // Strict Safety Rules to prevent Ban
        // 1. Minimum 60s delay between public event polls
        // 2. Exponential backoff if RateLimit-Remaining < 100
        // 3. Jittered sleep to simulate human activity
        
        let sleepTime = this.minSleep * this.backoffMultiplier;
        
        if (this.rateLimit.remaining < 100) {
            console.log(chalk.yellow(`\n[!] Safety Rule: Low rate limit (${this.rateLimit.remaining}). Forcing cooldown...`));
            sleepTime = 300000; // 5 minutes strict cooldown
        }

        const jitter = Math.floor(Math.random() * 10000);
        const totalSleep = sleepTime + jitter;

        process.stdout.write(chalk.gray(`\r[Safety Shield] Sleeping for ${Math.round(totalSleep/1000)}s | Limit: ${this.rateLimit.remaining} | Backoff: ${this.backoffMultiplier}x`));
        await new Promise(resolve => setTimeout(resolve, totalSleep));
    }

    async pollEvents() {
        console.log(chalk.cyan("Starting Real-time Event Monitor (GitHub Firehose)..."));
        
        while (this.isScanning) {
            try {
                const { data: events, headers } = await this.octokit.rest.activity.listPublicEvents({
                    per_page: 30
                });

                this.rateLimit.remaining = parseInt(headers['x-ratelimit-remaining']);
                this.rateLimit.reset = parseInt(headers['x-ratelimit-reset']);

                for (const event of events) {
                    if (event.type === "PushEvent") {
                        const repoName = event.repo.name;
                        const commits = event.payload.commits || [];
                        
                        for (const commit of commits) {
                            await this.analyzeDiff(repoName, commit.sha, commit.url.replace("api.github.com/repos", "github.com").replace("/commits/", "/commit/"));
                            
                            // Micro-sleep between commits to avoid spike detection
                            await new Promise(resolve => setTimeout(resolve, 500));
                        }
                    }
                }
                
                await this.waitSafety();
            } catch (error) {
                console.error(chalk.red("\nError polling events:"), error.message);
                await this.waitSafety();
            }
        }
    }

    async searchHistorical(query) {
        console.log(chalk.magenta(`Searching for historical leaks with query: "${query}"...`));
        try {
            const { data } = await this.octokit.rest.search.code({
                q: `${query} created:2026-01-01..2026-12-31`,
                per_page: 100
            });

            console.log(chalk.green(`Found ${data.total_count} potential files for query "${query}"`));
            
            for (const item of data.items) {
                // Find the pattern that matches this query to use its regex
                const pattern = PATTERNS.find(p => p.name.includes(query) || query.includes(p.name.split(' ')[0]));
                
                let match = "Context search required";
                let context = "Download file for full context.";

                try {
                    // Fetch raw file content to extract the exact match
                    const rawUrl = item.html_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/");
                    const fileResponse = await axios.get(rawUrl);
                    const content = fileResponse.data;

                    if (pattern && content) {
                        const matches = content.match(pattern.regex);
                        if (matches) {
                            match = matches[0].substring(0, 15) + "...";
                            
                            // Extract context
                            const lines = content.split('\n');
                            const matchLineIndex = lines.findIndex(l => l.includes(matches[0]));
                            context = lines.slice(Math.max(0, matchLineIndex - 2), Math.min(lines.length, matchLineIndex + 3)).join('\n');
                        }
                    }
                } catch (e) {
                    // Raw fetch might fail, keep default info
                }

                const intel = await userIntel.enrich(item.repository.owner.login);

                await this.logFinding({
                    name: pattern ? pattern.name : `Potential ${query} Match`,
                    repo: item.repository.full_name,
                    user: item.repository.owner.login,
                    file: item.path,
                    url: item.html_url,
                    severity: pattern ? pattern.severity : 'Unknown',
                    match: match,
                    context: context,
                    full_match: match === "Context search required" ? null : match,
                    user_intel: intel
                });
            }
        } catch (error) {
            console.error(chalk.red("Search error:"), error.message);
        }
    }

    async start() {
        this.isScanning = true;
        console.log(chalk.green.bold("\n--- GitHub Secret Scanner 2026 Started ---"));
        console.log(chalk.gray("System is now 100% automated. Monitoring and Searching in parallel.\n"));
        
        // Parallel Task 1: Real-time Event Monitor (The Firehose)
        this.pollEvents();

        // Parallel Task 2: Continuous Historical Intelligence Search
        this.continuousSearch();
    }

    async continuousSearch() {
        let patternIndex = 0;
        
        while (this.isScanning) {
            const pattern = PATTERNS[patternIndex];
            
            // Generate search query from pattern (extracting common prefix/string)
            const query = pattern.name.split(' ')[0]; 
            
            await this.searchHistorical(query);
            
            patternIndex = (patternIndex + 1) % PATTERNS.length;
            
            // Wait between searches to respect search API limits (stricter than events)
            // Search API has a limit of ~30 requests per minute for authenticated users
            await new Promise(resolve => setTimeout(resolve, 30000)); 
        }
    }
}

// Instantiate and start
const scanner = new GitHubScanner();
scanner.start();
