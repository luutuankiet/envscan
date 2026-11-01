# Maintainer identifiers live only in a local .env

This repo is public and its tool exists to keep identifying values out of commits, so it holds itself to that rule from its first commit: real names, hosts and addresses sit in a gitignored `.env`, one value per key, with neutral key names, and `.env.example` carries the meaning. The alternative, scrubbing before release, was rejected because public history cannot be cleaned cheaply.
