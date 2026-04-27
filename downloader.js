const axios = require("axios");
const fs = require("fs");
const path = require("path");
const chalk = require("chalk");

class LeakDownloader {
    constructor() {
        this.baseDir = path.join(__dirname, "leaks");
        if (!fs.existsSync(this.baseDir)) {
            fs.mkdirSync(this.baseDir);
        }
    }

    async download(fileUrl, fileName, repoName) {
        try {
            const repoDir = path.join(this.baseDir, repoName.replace("/", "_"));
            if (!fs.existsSync(repoDir)) {
                fs.mkdirSync(repoDir, { recursive: true });
            }

            const cleanFileName = fileName.replace(/[/\\?%*:|"<>]/g, '-');
            const filePath = path.join(repoDir, cleanFileName);

            const response = await axios.get(fileUrl, { responseType: 'stream' });
            const writer = fs.createWriteStream(filePath);

            response.data.pipe(writer);

            return new Promise((resolve, reject) => {
                writer.on('finish', () => {
                    console.log(chalk.green(`[↓] File Downloaded: ${filePath}`));
                    resolve(filePath);
                });
                writer.on('error', reject);
            });
        } catch (error) {
            console.error(chalk.red(`[!] Download failed: ${error.message}`));
            return null;
        }
    }
}

module.exports = new LeakDownloader();
