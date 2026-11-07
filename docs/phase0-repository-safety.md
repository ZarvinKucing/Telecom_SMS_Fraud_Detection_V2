# Phase 0: repository safety

## What was done
- A **new, separate repository** was created. The original repository was not modified, cloned into this tree, or copied from.
- `.gitignore` blocks `.env`, all `*.csv/*.xlsx/*.twbx/*.png` (except `docs/images`), `data/`, `out/` and exports.
- `.env.example` ships empty credential fields; `docker-compose.yml` refuses to start without them (`${VAR:?}`).
- Tests assert there are no hardcoded secrets and no string-formatted SQL in source.

## What could NOT be done, and why
- The original repository's files could not be inspected directly: the authoring sandbox has no network, and GitHub's file-tree pages
  disallow automated fetching. Only the public README was read. The statements about the original code and data come from the
  Technical Blueprint's own audit and were **not independently verified here**.

## Findings carried over from the blueprint (to be verified by the owner)
The blueprint reports that the public repository appears to contain operational telecom data (CDR CSVs, an Excel export, a Tableau
workbook with an embedded extract and a local path) and architecture/rule diagrams naming internal components and a working threshold.
Nothing from those files was reproduced here. The default thresholds in this project were chosen independently.

## Recommended actions on the ORIGINAL repository (need your approval; none were run)
1. Confirm with your internship agreement/supervisor what may be public. Make the repo **private** while cleaning.
2. Remove the CSVs, Excel export, Tableau workbook and images in a normal commit. **This does not remove them from Git history.**
3. To purge history, either start a fresh repository with a clean history (simplest), or rewrite history with `git filter-repo`:
   ```bash
   git clone --mirror <repo-url> repo-mirror.git && cd repo-mirror.git
   git filter-repo --invert-paths --path src/data --path src/export --path src/docs --path "src/src/visualitzation"
   # review, then force-push ONLY with explicit approval; collaborators must re-clone
   ```
   Also ask GitHub support to clear cached views and check forks. Anything already public may have been copied; cleaning cannot undo that.
4. Rotate any credential that ever appeared in history (the blueprint notes only an empty-password local pattern, no real secret).
