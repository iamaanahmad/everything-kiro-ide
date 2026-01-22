---
inclusion: always
---

# Coding Standards

## Core Principles

### Code Quality
- Write self-documenting code with clear variable and function names
- Keep functions small and focused (max 50 lines)
- Limit nesting depth to 4 levels maximum
- Use consistent indentation (2 spaces for JS/TS, 4 for Python)
- Remove dead code and unused imports immediately

### Security First
- Never hardcode secrets, API keys, or passwords
- Validate all user inputs and sanitize outputs
- Use parameterized queries to prevent SQL injection
- Implement proper authentication and authorization
- Log security events but never log sensitive data

### Performance Considerations
- Optimize for readability first, performance second
- Use appropriate data structures for the use case
- Implement caching where beneficial
- Avoid premature optimization
- Profile before optimizing

### Error Handling
- Use explicit error handling, avoid silent failures
- Provide meaningful error messages
- Log errors with sufficient context for debugging
- Implement graceful degradation where possible
- Use proper HTTP status codes for APIs

## Language-Specific Standards

### TypeScript/JavaScript
```typescript
// ✅ Good: Clear naming and type safety
interface UserProfile {
  id: string
  email: string
  createdAt: Date
}

async function getUserProfile(userId: string): Promise<UserProfile | null> {
  try {
    const user = await db.user.findUnique({ where: { id: userId } })
    return user ? mapToUserProfile(user) : null
  } catch (error) {
    logger.error('Failed to fetch user profile', { userId, error })
    throw new Error('Unable to retrieve user profile')
  }
}

// ❌ Bad: Unclear naming and no error handling
function getUser(id: any) {
  return db.user.findUnique({ where: { id } })
}
```

### Python
```python
# ✅ Good: Type hints and proper error handling
from typing import Optional
import logging

def calculate_user_score(user_id: str, metrics: dict[str, float]) -> Optional[float]:
    """Calculate user score based on provided metrics."""
    try:
        if not user_id or not metrics:
            return None
            
        score = sum(metrics.values()) / len(metrics)
        return round(score, 2)
    except (ValueError, ZeroDivisionError) as e:
        logging.error(f"Score calculation failed for user {user_id}: {e}")
        return None

# ❌ Bad: No type hints or error handling
def calc_score(uid, data):
    return sum(data.values()) / len(data)
```

## File Organization

### Project Structure
```
src/
├── components/          # Reusable UI components
├── pages/              # Route components
├── hooks/              # Custom React hooks
├── utils/              # Pure utility functions
├── services/           # API and external service calls
├── types/              # TypeScript type definitions
├── constants/          # Application constants
└── __tests__/          # Test files
```

### File Naming
- Use kebab-case for files: `user-profile.ts`
- Use PascalCase for components: `UserProfile.tsx`
- Use camelCase for utilities: `formatDate.ts`
- Add `.test.ts` or `.spec.ts` suffix for tests

## Documentation Standards

### Code Comments
```typescript
/**
 * Calculates the compound interest for an investment
 * @param principal - Initial investment amount
 * @param rate - Annual interest rate (as decimal, e.g., 0.05 for 5%)
 * @param time - Investment period in years
 * @param compound - Compounding frequency per year
 * @returns The final amount after compound interest
 */
function calculateCompoundInterest(
  principal: number,
  rate: number,
  time: number,
  compound: number = 1
): number {
  return principal * Math.pow(1 + rate / compound, compound * time)
}
```

### README Requirements
Every project must have:
- Clear project description and purpose
- Installation and setup instructions
- Usage examples
- API documentation (if applicable)
- Contributing guidelines
- License information

## Testing Standards

### Test Coverage
- Minimum 80% code coverage for all projects
- 100% coverage for critical business logic
- Test both happy path and error scenarios
- Include edge cases and boundary conditions

### Test Structure
```typescript
describe('UserService', () => {
  describe('getUserProfile', () => {
    it('should return user profile for valid user ID', async () => {
      // Arrange
      const userId = 'user-123'
      const mockUser = { id: userId, email: 'test@example.com' }
      jest.spyOn(db.user, 'findUnique').mockResolvedValue(mockUser)

      // Act
      const result = await getUserProfile(userId)

      // Assert
      expect(result).toEqual(expect.objectContaining({
        id: userId,
        email: 'test@example.com'
      }))
    })

    it('should return null for non-existent user', async () => {
      // Arrange
      jest.spyOn(db.user, 'findUnique').mockResolvedValue(null)

      // Act
      const result = await getUserProfile('invalid-id')

      // Assert
      expect(result).toBeNull()
    })

    it('should throw error when database fails', async () => {
      // Arrange
      jest.spyOn(db.user, 'findUnique').mockRejectedValue(new Error('DB Error'))

      // Act & Assert
      await expect(getUserProfile('user-123')).rejects.toThrow('Unable to retrieve user profile')
    })
  })
})
```

## Git Workflow Standards

### Commit Messages
Follow conventional commits format:
```
type(scope): description

feat(auth): add OAuth2 integration
fix(api): resolve user profile endpoint error
docs(readme): update installation instructions
refactor(utils): simplify date formatting logic
test(user): add edge case tests for user validation
```

### Branch Naming
- `feature/feature-name` for new features
- `fix/bug-description` for bug fixes
- `refactor/component-name` for refactoring
- `docs/section-name` for documentation updates

### Pull Request Requirements
- Clear title and description
- Link to related issues
- Include screenshots for UI changes
- Ensure all tests pass
- Request appropriate reviewers
- Update documentation if needed

## Code Review Checklist

### Functionality
- [ ] Code works as intended
- [ ] Edge cases are handled
- [ ] Error scenarios are covered
- [ ] Performance is acceptable

### Code Quality
- [ ] Code is readable and well-structured
- [ ] Functions are appropriately sized
- [ ] Variable names are descriptive
- [ ] No code duplication

### Security
- [ ] No hardcoded secrets
- [ ] Input validation is present
- [ ] Authentication/authorization is correct
- [ ] No sensitive data in logs

### Testing
- [ ] Tests cover new functionality
- [ ] Tests are meaningful and not just for coverage
- [ ] All tests pass
- [ ] No flaky tests introduced

## Enforcement

These standards are enforced through:
- Automated linting and formatting (ESLint, Prettier, Black)
- Pre-commit hooks for code quality checks
- CI/CD pipeline validation
- Code review requirements
- Regular team code review sessions

Remember: These standards exist to improve code quality, maintainability, and team collaboration. When in doubt, prioritize clarity and simplicity.