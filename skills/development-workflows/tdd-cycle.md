---
name: tdd-cycle
description: Complete Test-Driven Development workflow implementation. Enforces the RED-GREEN-REFACTOR cycle with comprehensive testing strategies.
---

# Test-Driven Development Cycle

This skill implements a complete TDD workflow that ensures high-quality, well-tested code through the disciplined application of the RED-GREEN-REFACTOR cycle.

## The TDD Cycle

```
🔴 RED → 🟢 GREEN → 🔵 REFACTOR → 🔄 REPEAT

RED:      Write a failing test that defines desired functionality
GREEN:    Write the minimal code needed to make the test pass
REFACTOR: Improve the code while keeping all tests green
REPEAT:   Move to the next piece of functionality
```

## When to Apply TDD

### Always Use TDD For:
- New feature development
- Bug fixes (write test that reproduces the bug first)
- API endpoint creation
- Business logic implementation
- Data validation and transformation
- Critical algorithms and calculations

### TDD is Especially Valuable For:
- Complex business rules
- Edge case handling
- Integration points between systems
- Security-sensitive code
- Performance-critical functions

## Step-by-Step TDD Process

### Phase 1: RED - Write a Failing Test

#### 1. Understand the Requirement
```typescript
// Example: Implement user email validation
// Requirement: Email must be valid format and not already exist in system

// Start by writing the test that describes the behavior
describe('UserService', () => {
  describe('validateUserEmail', () => {
    it('should return true for valid, unused email', async () => {
      // This test will fail initially because the method doesn't exist
      const userService = new UserService()
      const result = await userService.validateUserEmail('new@example.com')
      expect(result.isValid).toBe(true)
      expect(result.errors).toHaveLength(0)
    })
  })
})
```

#### 2. Write Comprehensive Test Cases
```typescript
describe('UserService.validateUserEmail', () => {
  let userService: UserService
  let mockUserRepository: jest.Mocked<UserRepository>

  beforeEach(() => {
    mockUserRepository = {
      findByEmail: jest.fn(),
    } as jest.Mocked<UserRepository>
    
    userService = new UserService(mockUserRepository)
  })

  // Happy path
  it('should return valid for properly formatted, unused email', async () => {
    mockUserRepository.findByEmail.mockResolvedValue(null)
    
    const result = await userService.validateUserEmail('valid@example.com')
    
    expect(result.isValid).toBe(true)
    expect(result.errors).toHaveLength(0)
  })

  // Edge cases and error conditions
  it('should return invalid for malformed email', async () => {
    const result = await userService.validateUserEmail('invalid-email')
    
    expect(result.isValid).toBe(false)
    expect(result.errors).toContain('Invalid email format')
  })

  it('should return invalid for empty email', async () => {
    const result = await userService.validateUserEmail('')
    
    expect(result.isValid).toBe(false)
    expect(result.errors).toContain('Email is required')
  })

  it('should return invalid for email that already exists', async () => {
    mockUserRepository.findByEmail.mockResolvedValue({
      id: '123',
      email: 'existing@example.com'
    } as User)
    
    const result = await userService.validateUserEmail('existing@example.com')
    
    expect(result.isValid).toBe(false)
    expect(result.errors).toContain('Email already exists')
  })

  it('should handle database errors gracefully', async () => {
    mockUserRepository.findByEmail.mockRejectedValue(new Error('Database connection failed'))
    
    const result = await userService.validateUserEmail('test@example.com')
    
    expect(result.isValid).toBe(false)
    expect(result.errors).toContain('Unable to validate email at this time')
  })
})
```

#### 3. Run Tests and Verify They Fail
```bash
npm test -- --testNamePattern="validateUserEmail"

# Expected output:
# FAIL src/services/UserService.test.ts
#   UserService
#     validateUserEmail
#       ✕ should return true for valid, unused email
#       ✕ should return invalid for malformed email
#       ...
# 
# Tests failed because UserService.validateUserEmail doesn't exist yet
```

### Phase 2: GREEN - Make Tests Pass

#### 1. Implement Minimal Code
```typescript
// Start with the simplest implementation that makes tests pass
interface EmailValidationResult {
  isValid: boolean
  errors: string[]
}

class UserService {
  constructor(private userRepository: UserRepository) {}

  async validateUserEmail(email: string): Promise<EmailValidationResult> {
    const errors: string[] = []

    // Handle empty email
    if (!email || email.trim() === '') {
      errors.push('Email is required')
      return { isValid: false, errors }
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    if (!emailRegex.test(email)) {
      errors.push('Invalid email format')
      return { isValid: false, errors }
    }

    // Check if email already exists
    try {
      const existingUser = await this.userRepository.findByEmail(email)
      if (existingUser) {
        errors.push('Email already exists')
        return { isValid: false, errors }
      }
    } catch (error) {
      errors.push('Unable to validate email at this time')
      return { isValid: false, errors }
    }

    return { isValid: true, errors: [] }
  }
}
```

#### 2. Run Tests and Verify They Pass
```bash
npm test -- --testNamePattern="validateUserEmail"

# Expected output:
# PASS src/services/UserService.test.ts
#   UserService
#     validateUserEmail
#       ✓ should return true for valid, unused email
#       ✓ should return invalid for malformed email
#       ✓ should return invalid for empty email
#       ✓ should return invalid for email that already exists
#       ✓ should handle database errors gracefully
```

### Phase 3: REFACTOR - Improve the Code

#### 1. Improve Implementation Quality
```typescript
class UserService {
  private static readonly EMAIL_REGEX = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/
  private logger = new Logger('UserService')

  constructor(private userRepository: UserRepository) {}

  async validateUserEmail(email: string): Promise<EmailValidationResult> {
    const errors: string[] = []

    // Normalize input
    const normalizedEmail = email?.trim().toLowerCase()

    // Validate presence
    if (!normalizedEmail) {
      return this.createValidationResult(false, ['Email is required'])
    }

    // Validate format
    if (!this.isValidEmailFormat(normalizedEmail)) {
      return this.createValidationResult(false, ['Invalid email format'])
    }

    // Check uniqueness
    try {
      const isUnique = await this.isEmailUnique(normalizedEmail)
      if (!isUnique) {
        return this.createValidationResult(false, ['Email already exists'])
      }
    } catch (error) {
      this.logger.error('Email validation failed', { email: normalizedEmail, error })
      return this.createValidationResult(false, ['Unable to validate email at this time'])
    }

    return this.createValidationResult(true, [])
  }

  private isValidEmailFormat(email: string): boolean {
    return UserService.EMAIL_REGEX.test(email)
  }

  private async isEmailUnique(email: string): Promise<boolean> {
    const existingUser = await this.userRepository.findByEmail(email)
    return existingUser === null
  }

  private createValidationResult(isValid: boolean, errors: string[]): EmailValidationResult {
    return { isValid, errors }
  }
}
```

#### 2. Run Tests Again to Ensure Refactoring Didn't Break Anything
```bash
npm test -- --testNamePattern="validateUserEmail"

# All tests should still pass after refactoring
```

#### 3. Add More Tests for Edge Cases (if needed)
```typescript
describe('UserService.validateUserEmail - Additional Edge Cases', () => {
  it('should handle email with mixed case correctly', async () => {
    mockUserRepository.findByEmail.mockResolvedValue(null)
    
    const result = await userService.validateUserEmail('Test@Example.COM')
    
    expect(result.isValid).toBe(true)
    expect(mockUserRepository.findByEmail).toHaveBeenCalledWith('test@example.com')
  })

  it('should handle email with whitespace', async () => {
    mockUserRepository.findByEmail.mockResolvedValue(null)
    
    const result = await userService.validateUserEmail('  test@example.com  ')
    
    expect(result.isValid).toBe(true)
    expect(mockUserRepository.findByEmail).toHaveBeenCalledWith('test@example.com')
  })

  it('should reject email with invalid TLD', async () => {
    const result = await userService.validateUserEmail('test@example.x')
    
    expect(result.isValid).toBe(false)
    expect(result.errors).toContain('Invalid email format')
  })
})
```

## Advanced TDD Patterns

### Outside-In TDD (London School)
```typescript
// Start with acceptance test (outside)
describe('User Registration API', () => {
  it('should register user with valid data', async () => {
    const userData = {
      email: 'newuser@example.com',
      name: 'New User',
      password: 'SecurePass123!'
    }

    const response = await request(app)
      .post('/api/users')
      .send(userData)
      .expect(201)

    expect(response.body).toMatchObject({
      id: expect.any(String),
      email: userData.email,
      name: userData.name
    })
  })
})

// Then work inward to unit tests
describe('UserController', () => {
  it('should call UserService.createUser with validated data', async () => {
    // Mock the service
    const mockUserService = {
      createUser: jest.fn().mockResolvedValue({ id: '123', email: 'test@example.com' })
    }

    const controller = new UserController(mockUserService)
    const req = { body: { email: 'test@example.com', name: 'Test' } }
    const res = { status: jest.fn().mockReturnThis(), json: jest.fn() }

    await controller.createUser(req, res)

    expect(mockUserService.createUser).toHaveBeenCalledWith(req.body)
    expect(res.status).toHaveBeenCalledWith(201)
  })
})
```

### Inside-Out TDD (Chicago School)
```typescript
// Start with unit tests (inside)
describe('EmailValidator', () => {
  it('should validate email format correctly', () => {
    const validator = new EmailValidator()
    
    expect(validator.isValid('test@example.com')).toBe(true)
    expect(validator.isValid('invalid-email')).toBe(false)
  })
})

// Build up to integration tests
describe('UserService', () => {
  it('should create user with valid email', async () => {
    const userService = new UserService(mockRepository, new EmailValidator())
    
    const result = await userService.createUser({
      email: 'test@example.com',
      name: 'Test User'
    })
    
    expect(result.email).toBe('test@example.com')
  })
})
```

## TDD Best Practices

### Test Naming Conventions
```typescript
// Good: Descriptive test names that explain behavior
describe('OrderCalculator', () => {
  describe('calculateTotal', () => {
    it('should return zero for empty order', () => {})
    it('should calculate total for single item', () => {})
    it('should apply discount when provided', () => {})
    it('should throw error for negative prices', () => {})
  })
})

// Bad: Vague test names
describe('OrderCalculator', () => {
  it('should work', () => {})
  it('should calculate', () => {})
  it('should handle errors', () => {})
})
```

### Test Structure (Arrange-Act-Assert)
```typescript
it('should calculate order total with tax', () => {
  // Arrange - Set up test data and dependencies
  const calculator = new OrderCalculator()
  const items = [
    { price: 10.00, quantity: 2 },
    { price: 5.00, quantity: 1 }
  ]
  const taxRate = 0.08

  // Act - Execute the behavior being tested
  const result = calculator.calculateTotal(items, taxRate)

  // Assert - Verify the expected outcome
  expect(result).toBe(27.00) // (10*2 + 5*1) * 1.08 = 27.00
})
```

### Mock Usage Guidelines
```typescript
// Good: Mock external dependencies, test behavior
describe('UserService', () => {
  it('should send welcome email after creating user', async () => {
    const mockEmailService = { sendWelcomeEmail: jest.fn() }
    const mockRepository = { save: jest.fn().mockResolvedValue(savedUser) }
    
    const userService = new UserService(mockRepository, mockEmailService)
    
    await userService.createUser(userData)
    
    expect(mockEmailService.sendWelcomeEmail).toHaveBeenCalledWith(savedUser.email)
  })
})

// Bad: Over-mocking, testing implementation details
describe('UserService', () => {
  it('should call repository save method', async () => {
    const mockRepository = { save: jest.fn() }
    const userService = new UserService(mockRepository)
    
    await userService.createUser(userData)
    
    expect(mockRepository.save).toHaveBeenCalled() // Testing implementation, not behavior
  })
})
```

## TDD Metrics and Quality Gates

### Coverage Requirements
```json
{
  "jest": {
    "coverageThreshold": {
      "global": {
        "branches": 80,
        "functions": 80,
        "lines": 80,
        "statements": 80
      },
      "./src/services/": {
        "branches": 90,
        "functions": 90,
        "lines": 90,
        "statements": 90
      }
    }
  }
}
```

### Test Quality Metrics
```typescript
// Measure test effectiveness
describe('Test Quality Metrics', () => {
  it('should have meaningful assertions', () => {
    // Good: Specific assertions
    expect(result.status).toBe('success')
    expect(result.data).toHaveLength(3)
    expect(result.data[0]).toMatchObject({ id: '1', name: 'Test' })
    
    // Bad: Vague assertions
    expect(result).toBeTruthy()
  })

  it('should test edge cases', () => {
    // Test boundary conditions
    expect(calculator.divide(10, 0)).toThrow('Division by zero')
    expect(validator.validate('')).toBe(false)
    expect(parser.parse(null)).toEqual({})
  })
})
```

## Common TDD Pitfalls and Solutions

### Pitfall 1: Writing Too Much Code at Once
```typescript
// Bad: Implementing entire feature before writing tests
class UserService {
  async createUser(userData) {
    // 50 lines of complex logic implemented all at once
    // without any tests guiding the design
  }
}

// Good: Incremental development guided by tests
// Test 1: Basic user creation
it('should create user with valid data', () => {})

// Implementation 1: Minimal code to pass
async createUser(userData) {
  return { id: '1', ...userData }
}

// Test 2: Email validation
it('should validate email format', () => {})

// Implementation 2: Add email validation
// ... and so on
```

### Pitfall 2: Testing Implementation Details
```typescript
// Bad: Testing internal implementation
it('should call validateEmail method', () => {
  const spy = jest.spyOn(userService, 'validateEmail')
  userService.createUser(userData)
  expect(spy).toHaveBeenCalled()
})

// Good: Testing behavior and outcomes
it('should reject user creation with invalid email', async () => {
  const userData = { email: 'invalid-email', name: 'Test' }
  
  await expect(userService.createUser(userData))
    .rejects.toThrow('Invalid email format')
})
```

### Pitfall 3: Skipping the RED Phase
```typescript
// Bad: Writing code first, then tests
class Calculator {
  add(a, b) { return a + b } // Code written first
}

// Test written after (might not catch bugs)
it('should add two numbers', () => {
  expect(calculator.add(2, 3)).toBe(5)
})

// Good: Test first, then implementation
it('should add two numbers', () => {
  expect(calculator.add(2, 3)).toBe(5) // This will fail initially
})

// Then implement
class Calculator {
  add(a, b) { return a + b }
}
```

## TDD Tools and Setup

### Jest Configuration for TDD
```json
{
  "scripts": {
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "tdd": "jest --watch --verbose"
  },
  "jest": {
    "testEnvironment": "node",
    "collectCoverageFrom": [
      "src/**/*.{ts,js}",
      "!src/**/*.test.{ts,js}",
      "!src/**/*.spec.{ts,js}"
    ],
    "testMatch": [
      "**/__tests__/**/*.(ts|js)",
      "**/*.(test|spec).(ts|js)"
    ]
  }
}
```

### VS Code Settings for TDD
```json
{
  "jest.autoRun": "watch",
  "jest.showCoverageOnLoad": true,
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.fixAll.eslint": true
  }
}
```

Remember: TDD is not just about testing - it's a design methodology. The tests drive the design of your code, leading to better architecture, clearer interfaces, and more maintainable solutions. The discipline of writing tests first forces you to think about how your code will be used before you write it, resulting in more user-friendly APIs and better separation of concerns.