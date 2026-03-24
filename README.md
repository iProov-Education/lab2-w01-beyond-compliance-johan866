# Privacy-First ID

Starter repo for the Beyond Compliance learning lab.

Most students only need GitHub Classroom, GitHub Codespaces, and the lab docs below.

## Start Here

1. Accept the GitHub Classroom invite shared by the instructors.
2. If GitHub shows a repository invitation, accept it before opening the repo.
3. Open your new repo in GitHub Codespaces.
4. Follow [ATTENDEE_QUICKSTART.md](ATTENDEE_QUICKSTART.md).
5. Start with [labs/README-lab-00-start.md](labs/README-lab-00-start.md).

## Quickstart

Recommended path:

- Use GitHub Codespaces and follow [ATTENDEE_QUICKSTART.md](ATTENDEE_QUICKSTART.md).
- If `pnpm dev` reports `tsx: not found`, run `pnpm install -r --frozen-lockfile && pnpm env:setup`, then retry.

Local terminal fallback:

- macOS: `./scripts/bootstrap-mac.sh`
- Windows PowerShell: `powershell -ExecutionPolicy Bypass -File .\\scripts\\bootstrap-windows.ps1`
- Create local env files: `pnpm env:setup`
- Install dependencies: `pnpm install -r --frozen-lockfile`
- Start the lab services: `pnpm dev`
- Open:
  - `http://localhost:3001`
  - `http://localhost:3002`

## Labs

- Lab 00: [labs/README-lab-00-start.md](labs/README-lab-00-start.md)
- Lab 01: [labs/README-lab-01-issuance.md](labs/README-lab-01-issuance.md)
- Lab 02: [labs/README-lab-02-bbs.md](labs/README-lab-02-bbs.md)
- Lab 03: [labs/README-lab-03-ohttp.md](labs/README-lab-03-ohttp.md)
- Lab 04: [labs/README-lab-04-iproov.md](labs/README-lab-04-iproov.md)
- Lab 05: [labs/README-lab-05-revocation.md](labs/README-lab-05-revocation.md)

## Docs

Student docs:

- Quick start: [ATTENDEE_QUICKSTART.md](ATTENDEE_QUICKSTART.md)
- Lesson guide: [LESSON_RUNBOOK.md](LESSON_RUNBOOK.md)
- Mobile wallet runbook: [STUDENT_WALLET_RUNBOOK.md](STUDENT_WALLET_RUNBOOK.md)
- Mobile wallet repo layout: [WALLET_FORKS.md](WALLET_FORKS.md)
- Deeper technical reference: [TECHNICAL_REFERENCE.md](TECHNICAL_REFERENCE.md)

Instructor and operator docs:

- GitHub Classroom operations: [COURSE_CLASSROOM.md](COURSE_CLASSROOM.md)
- Village demo conductor: [VILLAGE_DEMO_CONDUCTOR.md](VILLAGE_DEMO_CONDUCTOR.md)
