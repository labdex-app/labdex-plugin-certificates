# Certificates

A [labdex](https://github.com/reykimedev/labdex) plugin. Checks the TLS certificate of every https service in the inventory (and any other endpoints you list) and warns before they expire. Nothing leaves your network.

**Version** 1.0 · **Works with** labdex >=1.3,<2 · **Plugin id** `certificates`

> [!WARNING]
> Built with AI, for home labs only: labdex and its plugins were written largely with an AI
> coding assistant (Claude), directed and reviewed by a human. They haven't had an independent
> security audit and may contain security problems. Run them on a trusted home network.

## Install

It ships with labdex: **Plugins › Marketplace**, then *Install* (nothing is downloaded). Updates arrive through the official Marketplace (signed with the labdex project key).

## Settings

| Setting | Notes |
| --- | --- |
| Warn … days before expiry |  |
| Critical … days before expiry |  |
| Other endpoints | host:port or https://name[:port], e.g. mail.example.net:993 |
| Timeout per endpoint (seconds) |  |

## Actions

- **Check certificates** (run)

## Releasing

Bump `version` in `plugin.yaml`, add a `## <version>` section to `CHANGELOG.md`, commit, then
publish a GitHub release tagged `v<version>` (web UI, or `gh release create v<version> --target main --notes ""`).
The release workflow signs the plugin with the `LABDEX_SIGNING_KEY` secret, attaches the zip and
`CHANGELOG.md` to the release and puts that version's CHANGELOG section into its description.
Files listed in `.releaseignore` stay out of the zip.
