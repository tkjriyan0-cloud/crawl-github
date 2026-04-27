# GitHub Secret Scanner 2026

A high-performance, real-time monitoring and historical search tool designed to detect leaked API keys and secrets across all public GitHub repositories.

## 🚀 Features

- **Real-time Firehose**: Monitors the GitHub Public Events API for every push event globally.
- **Deep Diff Analysis**: Automatically fetches and scans commit diffs for high-confidence secret patterns.
- **Historical Search**: Scans for existing leaks specifically within the 2026 timeframe.
- **Premium Dashboard**: A sleek, dark-mode web interface to visualize findings in real-time.
- **Extensible Patterns**: Easily add new regex patterns to `patterns.js`.

## 🛠 Setup

1. **Install Dependencies**:
   ```bash
   npm install
   ```

2. **Configure Environment**:
   Edit the `.env` file and add your GitHub Personal Access Token (PAT):
   ```
   GITHUB_TOKEN=ghp_your_token_here
   ```
   *Note: Using a PAT is highly recommended to avoid strict rate limits.*

3. **Start the Tool**:
   ```bash
   node index.js
   ```

4. **Access the Dashboard**:
   Open your browser and navigate to `http://localhost:3000`.

## 🛡 Security Patterns

Currently detects:
- GitHub Personal Access Tokens
- AWS Access & Secret Keys
- Google API Keys
- Slack Bot Tokens & Webhooks
- Stripe Secret Keys
- Discord Tokens
- Firebase Configs
- Private Keys (RSA, EC, etc.)

## ⚠️ Disclaimer

This tool is intended for ethical security research and proactive data protection. Always respect GitHub's Terms of Service and use the collected data responsibly.

---
Built for the 2026 Security Initiative.
