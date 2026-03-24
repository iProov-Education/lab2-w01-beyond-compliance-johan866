# GitHub Classroom Operations

Instructor-facing guidance for running this repo through GitHub Classroom.

## Recommended model: one repo + `LAB_ID`

- Use a single student repo for the whole course.
- Set the active graded lab with the GitHub Actions variable `LAB_ID`.
- Keep branch-based lab detection only as a local fallback.

## Local grading commands

- Run one lab locally: `pnpm lab:check -- --lab 01`
- Run the same command GitHub Actions uses: `pnpm classroom:check`
- Force a specific lab locally: `LAB_ID=03 pnpm classroom:check`

If `3001` or `3002` are already in use locally, isolate the run with:

```bash
ISSUER_BASE_URL=http://127.0.0.1:3101 VERIFIER_BASE_URL=http://127.0.0.1:3102 pnpm lab:check -- --lab 01 --start
```

## Repo-level cohort operations

- Set the active lab on student repos:
  - `pnpm classroom:set-lab-id --repo owner/student-repo --lab 01`
  - `pnpm classroom:set-lab-id --classroom-csv accepted_assignments.csv --lab 02 --dry-run`
  - `pnpm classroom:set-lab-id --repos-file classroom-repos.txt --lab 02 --dry-run`
- Audit which repos are ready to advance:
  - `pnpm classroom:progress --classroom-csv accepted_assignments.csv`
  - `pnpm classroom:progress --classroom-csv accepted_assignments.csv --only-ready --json`
- Advance every repo currently on a specific lab:
  - `pnpm classroom:advance --classroom-csv accepted_assignments.csv --from 01`
  - `pnpm classroom:advance --classroom-csv accepted_assignments.csv --from 01 --apply`
- Require pass-first advancement only when you mean it:
  - `pnpm classroom:advance --classroom-csv accepted_assignments.csv --from 01 --only-ready`

## GitHub Classroom workflow

- Workflow file: `.github/workflows/classroom.yml`
- Student template scaffold: `node scripts/scaffold-classroom-template.js --clean`
- The autograder checks only the active `LAB_ID`.
- Students do not need to finish one lab before you move them to the next.

## iProov-Education rollout

- Instructor repo: `https://github.com/iProov-Education/LearningLab`
- Starter template repo: `https://github.com/iProov-Education/learninglab-starter`
- `course-ops` config: `learninglab-world-class-implementation-kit/catalog/course.config.iproov-education.yaml`
- Default conference assumption: keep assignment repos `public` to avoid paid private-repo collaborator seats for attendees.
- After you create the new GitHub Classroom in the `iProov-Education` org, update your instructor-only `course-ops` env file so `GITHUB_CLASSROOM_INVITE_URL` points at the new assignment and `GITHUB_CLASSROOM_STARTER_REPO_URL` points at `https://github.com/iProov-Education/learninglab-starter`.
- Google Classroom API limitation: `patch-google` cannot change coursework `materials`, so if the invite URL changes after publication you must edit the Google Classroom post in the UI or recreate the post.

## More detail

For the full student-template-oriented GitHub Classroom setup guide, see [classroom-template/COURSE_CLASSROOM.md](classroom-template/COURSE_CLASSROOM.md).
