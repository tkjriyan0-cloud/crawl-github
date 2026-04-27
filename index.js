const express = require('express');
const path = require('path');
const fs = require('fs');
const chalk = require('chalk');
const { exec } = require('child_process');

const app = express();
const PORT = process.env.PORT || 3000;

// Start the scanner in a separate process
console.log(chalk.blue('Starting Scanner Process...'));
const scannerProcess = exec('node scanner.js');

scannerProcess.stdout.on('data', (data) => {
    process.stdout.write(data);
});

scannerProcess.stderr.on('data', (data) => {
    process.stderr.write(data);
});

const db = require('./database');

// Serve dashboard
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// API for findings
app.get('/api/findings', async (req, res) => {
    let findings = [];
    const storage = JSON.parse(fs.readFileSync(path.join(__dirname, 'storage.json'), 'utf8'));

    if (db.client) {
        findings = await db.getAllFindings();
    } else {
        findings = storage.findings;
    }

    res.json({
        ...storage,
        findings: findings
    });
});

// Mock scanner state since it's in a separate process for now
// In a real app, you'd use a message bus or shared DB
app.get('/api/status', (req, res) => {
    res.json({
        status: 'active',
        safety_level: 'High',
        mode: 'Automatic'
    });
});

app.post('/api/clear', (req, res) => {
    const storagePath = path.join(__dirname, 'storage.json');
    const emptyStorage = {
        last_processed_event_id: null,
        findings: [],
        stats: {
            total_scanned_commits: 0,
            total_leaks_found: 0,
            start_time: new Date().toISOString()
        }
    };
    fs.writeFileSync(storagePath, JSON.stringify(emptyStorage, null, 4));
    res.json({ success: true });
});

app.listen(PORT, () => {
    console.log(chalk.green.bold(`\n🚀 Dashboard available at http://localhost:${PORT}`));
    console.log(chalk.gray('Use the dashboard to monitor leaks in real-time.'));
});
