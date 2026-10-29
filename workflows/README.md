# AegisDNS CI/CD Workflows

This directory contains the GitHub Actions CI/CD workflows for AegisDNS.

### Workflows Included:
- **`app-build.yml`**: Full multi-stage build and test pipeline (tests the Python core, verifies the Go networking stack, and builds the Android debug APK).
- **`android.yml`**: Automated Android lint and assembly.
- **`android-tv.yml`**: Android TV flavor build.
- **`codeql.yml`**: Automated security scanning.
- **`izzyondroid.yml`**: IzzyOnDroid release builder.

### How to Enable on GitHub:
To activate GitHub Actions, copy the desired workflow (e.g., `app-build.yml`) into `.github/workflows/`:

```bash
mkdir -p .github/workflows
cp workflows/app-build.yml .github/workflows/
git add .github/workflows
git commit -m "ci: enable app build workflow"
git push origin main
```

*(Note: Pushing directly to `.github/workflows/` requires a GitHub Personal Access Token with the `workflow` scope enabled).*
