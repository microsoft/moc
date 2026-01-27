# GitHub Copilot Instructions for MOC Repository

## Pull Request Workflow

### Before Marking PR as Ready for Review

When creating or working on a pull request, you **MUST** ensure all of the following conditions are met before marking the PR as ready for review:

#### 1. Build Status Checks
- ✅ All build jobs must pass successfully
- ✅ Azure Pipelines build jobs must complete without errors:
  - `Build` job (includes protobuf generation, compilation, and unit tests)
  - `Lint` job (GolangCI-Lint must pass)
- ✅ GitHub Actions workflows must complete successfully:
  - CodeQL analysis must complete without blocking issues

#### 2. Test Status Checks
- ✅ All unit tests must pass (`make unittest`)
- ✅ No test failures or regressions introduced by the changes
- ✅ Test coverage should be maintained or improved

#### 3. Code Quality Checks
- ✅ Linting must pass without errors (`make golangci-lint`)
- ✅ No new linting violations introduced by the changes
- ✅ Code follows the existing style and conventions of the repository

#### 4. CI/CD Pipeline Status
- ✅ All Azure Pipelines jobs must show green/passing status
- ✅ All GitHub Actions workflows must show green/passing status
- ✅ No pending or failing status checks on the PR

#### 5. Build Verification
- ✅ The code must build successfully:
  - `make generate` completes without errors (protobuf generation)
  - `make all` completes without errors (full build)
- ✅ No compilation errors or warnings that would block the build

### How to Verify Status

Before marking a PR as ready for review, use GitHub CLI or API to verify:

```bash
# Check PR status checks
gh pr checks <pr-number>

# Verify all checks are passing
gh pr view <pr-number> --json statusCheckRollup
```

Or check the PR page on GitHub to ensure:
- All status checks show green checkmarks (✓)
- No red X marks or orange/yellow pending indicators
- The "All checks have passed" message is displayed

### Exception Handling

If any checks fail:
1. **DO NOT** mark the PR as ready for review
2. Investigate and fix the failing checks first
3. Wait for all checks to re-run and pass
4. Only then mark the PR as ready for review

If a check failure is unrelated to your changes:
1. Document the pre-existing failure in the PR description
2. Ensure your changes don't make it worse
3. Consider fixing the pre-existing issue if feasible
4. Communicate with maintainers about the unrelated failure

### Draft PR Usage

- Use draft PRs for work-in-progress changes
- Keep PR in draft status until all checks pass
- Convert to ready for review only after all status checks are green

## Build Commands Reference

- `make generate` - Generate protobuf files
- `make all` - Build all components
- `make unittest` - Run unit tests
- `make golangci-lint` - Run linting checks
- `make pipeline` - Generate protobuf for pipeline

## Additional Guidelines

- Always run local builds and tests before pushing
- Ensure changes are minimal and focused
- Keep PR descriptions clear and informative
- Update documentation if behavior changes
- Follow existing code patterns and conventions
