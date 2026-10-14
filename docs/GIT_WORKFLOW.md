# Git Workflow

How work moves from an idea to the `main` branch on GitHub. We use **GitHub flow**: `main` always works, and every change happens on its own short-lived branch that is merged back through a pull request.

---

## The rules

1. **`main` is always working and tested.** Nothing is committed to `main` directly (except the very first commit).
2. **One branch per piece of work**: one roadmap step, one fix, or one docs change.
3. **Every branch reaches `main` through a pull request (PR)**, which is where the change is read once more before it lands.
4. **Start every piece of work from an up-to-date `main`.**
5. **Delete a branch once it is merged.**
6. **Mohit runs every git command.** The AI assistant suggests branch names, commit messages and PR descriptions, and never commits or pushes.

## Branch names

`<type>/<short-description>`, lowercase, words joined with hyphens.

| Type | Use for | Example |
|---|---|---|
| `feature/` | New behaviour (a roadmap step) | `feature/error-handling-and-headers` |
| `fix/` | Repairing something broken | `fix/health-check-timeout` |
| `docs/` | Documentation only | `docs/git-workflow` |
| `chore/` | Tooling, dependencies, scripts | `chore/upgrade-spring-boot` |

## Commit messages

- Start with a verb, describe what changed: `Add trace IDs to error responses`.
- Under about 70 characters for the first line. Add detail on later lines if needed.
- Several small commits on a branch are fine; each should leave the code working.

## The everyday cycle

```
 main ──●───────────────────────────●────────▶   (always working)
         \                         /
          ●──●──●  feature/xyz ───●             (your work)
          ^  ^  ^                 ^
       commit commit commit    merged by a pull request
```

All commands run from the project folder (`...\Desktop\<project>`).

### 1. Start from the latest `main`
```powershell
git switch main
git pull
```
`git switch main` moves you onto `main`. `git pull` brings down anything merged on GitHub since you last looked.

### 2. Create a branch for the work
```powershell
git switch -c feature/error-handling-and-headers
```
`-c` means *create*. You are now on the new branch; `main` is untouched.

### 3. Build and test
The assistant builds; you test. Check where you are at any time:
```powershell
git status
git branch
```
`git branch` lists your branches; the current one has a `*`.

### 4. Commit
```powershell
git add .
git status
git commit -m "Add catch-all error handler with trace IDs"
```
Always read `git status` before committing. Nothing named `.env`, no `target/` folder, and no `handbook/` should ever be listed.

### 5. Push the branch to GitHub
First push of a new branch:
```powershell
git push -u origin feature/error-handling-and-headers
```
`-u` links your local branch to the one on GitHub, so later pushes on this branch are just `git push`.

### 6. Open a pull request
On GitHub, a yellow banner offers **Compare & pull request**. Use it. Or: **Pull requests → New pull request**, base `main`, compare your branch.
- **Title**: what the change does.
- **Description**: what, why, how it was tested (the assistant drafts this).
- Read the **Files changed** tab once yourself. That is the review.

### 7. Merge
Click **Merge pull request → Create a merge commit → Confirm**, then **Delete branch**.

### 8. Tidy up locally
```powershell
git switch main
git pull
git branch -d feature/error-handling-and-headers
```
`-d` deletes the local branch; git refuses if it was not merged, which is a useful safety check.

Then back to step 1 for the next piece of work.

## Doing the same in VS Code

| Command | VS Code |
|---|---|
| `git switch <branch>` | Click the branch name in the bottom-left corner, pick a branch |
| `git switch -c <branch>` | Same menu → **Create new branch...** |
| `git status` | **Source Control** panel (Ctrl+Shift+G) |
| `git add` | **+** next to a file, or next to "Changes" for all |
| `git commit` | Type the message in the box, press **Commit** |
| `git push` | **Sync Changes** / **Publish Branch** button |
| `git pull` | **...** menu → **Pull** |

The command line is used in these instructions because it shows exactly what happens.

## First-time setup (once only)

1. Turn the folder into a repository and make the first commit on `main`:
   ```powershell
   git init -b main
   git add .
   git status
   git commit -m "Initial commit: gateway with PostgreSQL, signup, login, token sessions and roles"
   ```
2. Create the GitHub repository and push, **either**:
   - **VS Code:** Source Control → **Publish Branch** → choose the name and *private* or *public*. VS Code creates the repository on GitHub and pushes `main`. **Or:**
   - **github.com:** **New repository**, same name, **leave README, .gitignore and licence unticked** (the repository must be empty), then:
     ```powershell
     git remote add origin https://github.com/<username>/<repo>.git
     git push -u origin main
     ```
3. From then on, use the everyday cycle.

## When something goes wrong

| Situation | What to do |
|---|---|
| Made changes on `main` by mistake (not committed yet) | `git switch -c feature/<name>`: the changes come with you to the new branch |
| Committed to `main` by mistake (not pushed) | Ask before doing anything; it is fixable without losing work |
| `git pull` says there are conflicts | Stop and ask. A conflict means two changes touched the same lines; it is resolved by choosing what the file should say |
| Want to see what changed before committing | `git diff` (unstaged) or `git diff --staged` (staged) |
| Want to throw away changes to one file | `git restore <file>` (this cannot be undone) |
| `.env` or another secret appears in `git status` | Do **not** commit. Check `.gitignore`, then ask |
| A secret was pushed to GitHub | Treat it as leaked: generate a new one immediately (deleting the commit is not enough) |

## What happens at each roadmap step

| When | Who | What |
|---|---|---|
| Start of a step | Assistant | Gives the branch name and the two commands from steps 1–2 |
| During the step | Assistant | Builds and narrates |
| End of the step | Mohit | Tests, as described by the assistant |
| End of the step | Assistant | Gives the commit message(s), PR title and PR description |
| End of the step | Mohit | Commits, pushes, opens the PR, reviews, merges, tidies up |
