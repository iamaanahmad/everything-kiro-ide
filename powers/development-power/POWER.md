# Development Power

**Comprehensive development workflows for code review, testing, debugging, and quality assurance.**

## Overview

The Development Power provides battle-tested workflows and best practices for software development. It includes guidance for code review, test-driven development, debugging strategies, and quality assurance processes.

This power uses **documentation and steering files only** - no MCP servers required. It's designed to guide Kiro's behavior during development tasks.

---

## Features

- **Code Review Workflows** - Systematic code review processes
- **Test-Driven Development** - TDD methodology and best practices
- **Debugging Strategies** - Effective debugging techniques
- **Quality Assurance** - QA checklists and processes
- **Best Practices** - Industry-standard development practices

---

## Quick Start

1. **Activate the power:**
   ```
   activate development-power
   ```

2. **Read a workflow guide:**
   ```
   read steering code-review-process.md from development-power
   ```

3. **Use in your workflow:**
   ```
   Review this code following the development power guidelines
   ```

---

## Available Steering Files

### 1. code-review-process.md
**Purpose:** Systematic code review workflow

**When to use:**
- Before merging pull requests
- During pair programming sessions
- When reviewing security-critical code

**Key topics:**
- Security review checklist
- Performance analysis
- Code quality assessment
- Best practices verification

### 2. tdd-workflow.md
**Purpose:** Test-driven development methodology

**When to use:**
- Implementing new features
- Fixing bugs
- Refactoring existing code

**Key topics:**
- RED-GREEN-REFACTOR cycle
- Writing effective tests
- Test coverage requirements
- Mocking and stubbing

### 3. debugging-strategies.md
**Purpose:** Effective debugging techniques

**When to use:**
- Investigating bugs
- Performance issues
- Unexpected behavior

**Key topics:**
- Systematic debugging approach
- Log analysis
- Reproduction steps
- Root cause analysis

### 4. quality-assurance.md
**Purpose:** QA processes and checklists

**When to use:**
- Before releases
- During feature completion
- Quality gate validation

**Key topics:**
- Testing checklist
- Performance validation
- Security verification
- Documentation review

---

## Workflows

### Workflow 1: Code Review

```
User: Review this pull request

Kiro: [Activates development-power]
[Reads code-review-process.md]

Following systematic code review process:

1. Security Analysis
   - Checking for vulnerabilities...
   - Input validation: ✓
   - Authentication: ✓
   - SQL injection risks: None found

2. Performance Review
   - Algorithm complexity: O(n) - Good
   - Database queries: Optimized
   - Caching: Implemented

3. Code Quality
   - Function size: Within limits
   - Naming: Clear and descriptive
   - Error handling: Comprehensive

4. Test Coverage
   - Unit tests: 85% ✓
   - Integration tests: Present ✓
   - E2E tests: Recommended for checkout flow

Recommendation: APPROVE with suggestion to add E2E tests
```

### Workflow 2: TDD Implementation

```
User: Implement user authentication with TDD

Kiro: [Activates development-power]
[Reads tdd-workflow.md]

Following TDD methodology:

STEP 1 (RED): Write failing test
```typescript
describe('UserAuth', () => {
  it('should authenticate valid user', async () => {
    const result = await auth.login('user@example.com', 'password')
    expect(result.success).toBe(true)
    expect(result.token).toBeDefined()
  })
})
```

Running test... ❌ FAILED (expected - no implementation)

STEP 2 (GREEN): Minimal implementation
[Creates auth.login() function]

Running test... ✅ PASSED

STEP 3 (REFACTOR): Improve code
[Refactors while keeping tests green]

Coverage: 90% ✓
```

### Workflow 3: Debugging

```
User: Help debug this performance issue

Kiro: [Activates development-power]
[Reads debugging-strategies.md]

Systematic debugging approach:

1. Reproduce the issue
   - Can you provide steps to reproduce?
   - What's the expected vs actual behavior?

2. Gather information
   - Checking logs...
   - Analyzing performance metrics...
   - Reviewing recent changes...

3. Form hypothesis
   - Potential cause: N+1 query problem in user endpoint
   - Evidence: Database query count increases with users

4. Test hypothesis
   - Adding query logging...
   - Confirmed: 100 queries for 100 users

5. Implement fix
   - Using eager loading with includes
   - Reduced to 2 queries total

6. Verify fix
   - Performance improved: 2000ms → 50ms ✓
   - No regressions in tests ✓
```

---

## Best Practices

### Code Review
- ✅ Review security first (CRITICAL issues)
- ✅ Check performance implications
- ✅ Verify test coverage (80%+ required)
- ✅ Ensure documentation is updated
- ✅ Provide constructive feedback

### Test-Driven Development
- ✅ Write test FIRST, before implementation
- ✅ Run test and verify it FAILS
- ✅ Write minimal code to pass
- ✅ Refactor while keeping tests green
- ✅ Maintain 80%+ coverage

### Debugging
- ✅ Reproduce the issue consistently
- ✅ Gather all relevant information
- ✅ Form and test hypotheses systematically
- ✅ Document findings and solutions
- ✅ Add tests to prevent regression

### Quality Assurance
- ✅ Run full test suite before release
- ✅ Perform security audit
- ✅ Validate performance benchmarks
- ✅ Review documentation completeness
- ✅ Check accessibility compliance

---

## Integration with Agents

This power works seamlessly with Kiro agents:

### With code-reviewer Agent
```
User: Review this code using development power guidelines

Kiro: [Activates development-power]
[Invokes code-reviewer agent]
[Applies code-review-process.md guidelines]
```

### With test-engineer Agent
```
User: Implement tests following TDD

Kiro: [Activates development-power]
[Invokes test-engineer agent]
[Follows tdd-workflow.md methodology]
```

### With debug-detective Agent
```
User: Debug this issue systematically

Kiro: [Activates development-power]
[Invokes debug-detective agent]
[Uses debugging-strategies.md approach]
```

---

## Examples

### Example 1: Security-Focused Code Review

```
User: Review this authentication code for security issues

Kiro: Activating development-power for security review...

Security Analysis (from code-review-process.md):

CRITICAL Issues:
- [Line 45] Hardcoded JWT secret
  Fix: Move to environment variable

HIGH Issues:
- [Line 67] Password stored in plain text
  Fix: Use bcrypt hashing

MEDIUM Issues:
- [Line 89] No rate limiting on login endpoint
  Fix: Implement rate limiting middleware

Recommendation: BLOCK until CRITICAL and HIGH issues resolved
```

### Example 2: TDD for New Feature

```
User: Add password reset feature using TDD

Kiro: Activating development-power for TDD workflow...

Phase 1: Define Interface
```typescript
interface PasswordResetService {
  requestReset(email: string): Promise<ResetToken>
  validateToken(token: string): Promise<boolean>
  resetPassword(token: string, newPassword: string): Promise<void>
}
```

Phase 2: Write Tests (RED)
[Creates comprehensive test suite]

Phase 3: Implement (GREEN)
[Implements minimal code to pass]

Phase 4: Refactor (IMPROVE)
[Improves code quality]

Phase 5: Verify Coverage
Coverage: 95% ✓ (exceeds 80% requirement)
```

### Example 3: Performance Debugging

```
User: API endpoint is slow, help debug

Kiro: Activating development-power for debugging...

Following systematic debugging approach:

1. Reproduce: GET /api/users takes 3000ms
2. Gather info: 
   - Database queries: 150 queries
   - Memory usage: Normal
   - CPU usage: Normal
3. Hypothesis: N+1 query problem
4. Test: Added query logging - CONFIRMED
5. Fix: Implemented eager loading
6. Verify: Response time now 80ms ✓

Root cause: N+1 queries loading user posts
Solution: Use .include() for eager loading
```

---

## Troubleshooting

### Power Not Activating

**Problem:** Development power doesn't activate

**Solution:**
1. Check power is installed: `list powers`
2. Verify power.json exists in power directory
3. Restart Kiro if needed

### Steering Files Not Found

**Problem:** "Steering file not found"

**Solution:**
1. Check file exists in `steering/` directory
2. Use exact filename including .md extension
3. Verify power is activated first

### Guidelines Not Being Followed

**Problem:** Kiro not following power guidelines

**Solution:**
1. Explicitly activate power before use
2. Reference specific steering file
3. Be specific in your request

---

## Customization

You can customize this power for your team:

### 1. Add Team-Specific Guidelines

Create `steering/team-standards.md`:
```markdown
# Team Development Standards

## Our Specific Rules
- Use TypeScript strict mode
- Minimum 90% test coverage
- All PRs require 2 approvals
- Security review for auth changes
```

### 2. Modify Existing Workflows

Edit `steering/code-review-process.md` to add:
- Team-specific checklists
- Custom quality gates
- Project-specific requirements

### 3. Add New Steering Files

Create new guides for:
- Deployment procedures
- Incident response
- Architecture decisions
- Performance benchmarks

---

## Version History

### v1.0.0 (2026-04-30)
- Initial release
- Code review process
- TDD workflow
- Debugging strategies
- Quality assurance guidelines

---

## Contributing

Want to improve this power?

1. Fork the repository
2. Add/improve steering files
3. Test in real projects
4. Submit pull request

---

**The Development Power provides battle-tested workflows to improve code quality, testing, and debugging. Activate it at the start of your development session for guided best practices!**
