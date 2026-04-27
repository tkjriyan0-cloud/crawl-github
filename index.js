const express = require('express');
const path = require('path');
const fs = require('fs');
const chalk = require('chalk');
const { exec } = require('child_process');

const app = express();
const PORT = 3000;

// Start the scanner in a separate process
console.log(chalk.blue('Starting Scanner Process...'));
const scannerProcess = exec('node scanner.js');

scannerProcess.stdout.on('data', (data) => {
    process.stdout.write(data);
});

scannerProcess.stderr.on('data', (data) => {
    process.stderr.write(data);
});

// Serve dashboard
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// API for findings
app.get('/api/findings', (req, res) => {
    const storage = JSON.parse(fs.readFileSync(path.join(__dirname, 'storage.json'), 'utf8'));
    res.json(storage);
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

app.listen(PORT, () => {
    console.log(chalk.green.bold(`\n🚀 Dashboard available at http://localhost:${PORT}`));
    console.log(chalk.gray('Use the dashboard to monitor leaks in real-time.'));
});
