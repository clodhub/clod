# Workflow

Push `main` with `GITHUB_TOKEN` and `GH_TOKEN` unset (`env -u GITHUB_TOKEN -u GH_TOKEN git push`), so `gh`'s keyring login is used. Releases and catalogue publishing happen on George's go.
Read-only references: `/Users/george/Projects/com/my/{mcinpoker,skull}`.

From this checkout: `python3 -m clod --help`; checks: `python3 -B -m unittest discover -s tests`. Package review check: `CLOD_REVIEW_SOURCE=/absolute/package python3 -B -m unittest tests.test_packaged_review -v` for a dependency-free real package.
Always run Python with `-B`.
Update snapshots reject symbolic links, including installed dependency links; a fresh proposal does not bypass this.
