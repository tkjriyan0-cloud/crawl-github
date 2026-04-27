const { Octokit } = require("octokit");
require("dotenv").config();

class UserIntel {
    constructor() {
        this.octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });
    }

    async enrich(username) {
        try {
            const { data } = await this.octokit.rest.users.getByUsername({
                username: username
            });

            return {
                name: data.name || "N/A",
                email: data.email || "Private",
                location: data.location || "Unknown",
                bio: data.bio || "",
                blog: data.blog || "",
                twitter: data.twitter_username || "",
                public_repos: data.public_repos,
                followers: data.followers,
                profile_url: data.html_url
            };
        } catch (error) {
            return null;
        }
    }
}

module.exports = new UserIntel();
