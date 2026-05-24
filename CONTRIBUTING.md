# Contributing

This repository is public and source-available for integration transparency.
It is not permissive open source; contributions are accepted only under the
terms in [LICENSE](LICENSE) and the repository's contribution process.

## Development

Use Node 18 or later.

```sh
npm install
npm run lint
npm run typecheck
npm test
npm run build
npm pack --dry-run
```

## Pull Requests

- Keep changes scoped to the SDK, tests, and public documentation.
- Add or update tests for behavioral changes.
- Update [CHANGELOG.md](CHANGELOG.md) for public API, packaging, or release
  changes.
- Do not add tenant-specific examples, API keys, raw customer prompts, `.env`
  files, generated tarballs, or local test artifacts.
- Optional framework integrations must remain optional for consumers that only
  use the core client.

## Release Notes

The release workflow publishes the version in `package.json` from `main`.
If a Git tag exists without a corresponding npm version, recover by bumping to
the next patch version instead of reusing the stuck version.

