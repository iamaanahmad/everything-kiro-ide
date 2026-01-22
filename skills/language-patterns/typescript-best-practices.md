# TypeScript Best Practices

A comprehensive guide to writing maintainable, type-safe, and performant TypeScript code.

## Type System Mastery

### Advanced Type Patterns

```typescript
// Utility types for better type safety
type NonNullable<T> = T extends null | undefined ? never : T
type RequiredKeys<T> = {
  [K in keyof T]-?: {} extends Pick<T, K> ? never : K
}[keyof T]

// Conditional types for API responses
type ApiResponse<T> = T extends string
  ? { message: T }
  : T extends object
  ? { data: T; meta: ResponseMeta }
  : never

// Template literal types for type-safe routing
type Route = `/api/${'users' | 'products' | 'orders'}/${string}`
type Method = 'GET' | 'POST' | 'PUT' | 'DELETE'

// Branded types for domain modeling
type UserId = string & { readonly brand: unique symbol }
type Email = string & { readonly brand: unique symbol }

function createUserId(id: string): UserId {
  // Validation logic here
  return id as UserId
}

// Discriminated unions for state management
type LoadingState = 
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'success'; data: any }
  | { status: 'error'; error: string }

function handleState(state: LoadingState) {
  switch (state.status) {
    case 'idle':
      return 'Ready to load'
    case 'loading':
      return 'Loading...'
    case 'success':
      return `Loaded: ${state.data}` // TypeScript knows data exists
    case 'error':
      return `Error: ${state.error}` // TypeScript knows error exists
  }
}
```

### Generic Constraints and Inference

```typescript
// Generic constraints for better type safety
interface Identifiable {
  id: string
}

interface Timestamped {
  createdAt: Date
  updatedAt: Date
}

// Constrained generics
function updateEntity<T extends Identifiable & Timestamped>(
  entity: T,
  updates: Partial<Omit<T, 'id' | 'createdAt'>>
): T {
  return {
    ...entity,
    ...updates,
    updatedAt: new Date()
  }
}

// Mapped types with key remapping
type Getters<T> = {
  [K in keyof T as `get${Capitalize<string & K>}`]: () => T[K]
}

type UserGetters = Getters<{ name: string; age: number }>
// Result: { getName: () => string; getAge: () => number }

// Recursive types for nested structures
type DeepReadonly<T> = {
  readonly [P in keyof T]: T[P] extends object ? DeepReadonly<T[P]> : T[P]
}

// Function overloads with proper typing
function createElement(tag: 'div'): HTMLDivElement
function createElement(tag: 'span'): HTMLSpanElement
function createElement(tag: 'input'): HTMLInputElement
function createElement(tag: string): HTMLElement
function createElement(tag: string): HTMLElement {
  return document.createElement(tag)
}
```

## Error Handling Patterns

### Result Type Pattern

```typescript
// Result type for functional error handling
type Result<T, E = Error> = 
  | { success: true; data: T }
  | { success: false; error: E }

class ResultUtils {
  static ok<T>(data: T): Result<T> {
    return { success: true, data }
  }

  static err<E>(error: E): Result<never, E> {
    return { success: false, error }
  }

  static map<T, U, E>(
    result: Result<T, E>,
    fn: (data: T) => U
  ): Result<U, E> {
    return result.success
      ? ResultUtils.ok(fn(result.data))
      : result
  }

  static flatMap<T, U, E>(
    result: Result<T, E>,
    fn: (data: T) => Result<U, E>
  ): Result<U, E> {
    return result.success ? fn(result.data) : result
  }
}

// Usage example
async function fetchUser(id: string): Promise<Result<User, ApiError>> {
  try {
    const response = await fetch(`/api/users/${id}`)
    if (!response.ok) {
      return ResultUtils.err({
        code: response.status,
        message: 'Failed to fetch user'
      })
    }
    const user = await response.json()
    return ResultUtils.ok(user)
  } catch (error) {
    return ResultUtils.err({
      code: 500,
      message: error.message
    })
  }
}

// Chaining operations
const processUser = async (id: string) => {
  const userResult = await fetchUser(id)
  
  return ResultUtils.flatMap(userResult, user =>
    ResultUtils.map(
      validateUser(user),
      validUser => transformUser(validUser)
    )
  )
}
```

### Custom Error Classes

```typescript
// Base error class with proper inheritance
abstract class AppError extends Error {
  abstract readonly code: string
  abstract readonly statusCode: number
  
  constructor(message: string, public readonly context?: Record<string, any>) {
    super(message)
    this.name = this.constructor.name
    
    // Maintains proper stack trace for where our error was thrown
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor)
    }
  }

  toJSON() {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      statusCode: this.statusCode,
      context: this.context
    }
  }
}

class ValidationError extends AppError {
  readonly code = 'VALIDATION_ERROR'
  readonly statusCode = 400

  constructor(
    message: string,
    public readonly field: string,
    context?: Record<string, any>
  ) {
    super(message, { ...context, field })
  }
}

class NotFoundError extends AppError {
  readonly code = 'NOT_FOUND'
  readonly statusCode = 404

  constructor(resource: string, id: string) {
    super(`${resource} with id ${id} not found`, { resource, id })
  }
}

// Error boundary for React components
interface ErrorBoundaryState {
  hasError: boolean
  error?: Error
}

class ErrorBoundary extends React.Component<
  React.PropsWithChildren<{}>,
  ErrorBoundaryState
> {
  constructor(props: React.PropsWithChildren<{}>) {
    super(props)
    this.state = { hasError: false }
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('Error caught by boundary:', error, errorInfo)
    // Send to error reporting service
  }

  render() {
    if (this.state.hasError) {
      return <ErrorFallback error={this.state.error} />
    }

    return this.props.children
  }
}
```

## Performance Optimization

### Lazy Loading and Code Splitting

```typescript
// Dynamic imports with proper typing
const LazyComponent = React.lazy(() => 
  import('./HeavyComponent').then(module => ({
    default: module.HeavyComponent
  }))
)

// Preload components based on user interaction
const preloadComponent = () => {
  const componentImport = () => import('./HeavyComponent')
  
  // Preload on hover
  const handleMouseEnter = () => {
    componentImport()
  }
  
  return { handleMouseEnter }
}

// Route-based code splitting
const routes = [
  {
    path: '/dashboard',
    component: React.lazy(() => import('./pages/Dashboard'))
  },
  {
    path: '/profile',
    component: React.lazy(() => import('./pages/Profile'))
  }
] as const

// Webpack magic comments for chunk naming
const DashboardPage = React.lazy(() => 
  import(
    /* webpackChunkName: "dashboard" */
    /* webpackPreload: true */
    './pages/Dashboard'
  )
)
```

### Memoization Patterns

```typescript
// Custom memoization hook with dependencies
function useMemoizedCallback<T extends (...args: any[]) => any>(
  callback: T,
  deps: React.DependencyList
): T {
  return React.useCallback(callback, deps)
}

// Memoized selector pattern
const createMemoizedSelector = <T, R>(
  selector: (state: T) => R
) => {
  let lastState: T
  let lastResult: R
  
  return (state: T): R => {
    if (state !== lastState) {
      lastState = state
      lastResult = selector(state)
    }
    return lastResult
  }
}

// Usage with Redux-like state
const selectUsersByRole = createMemoizedSelector(
  (state: AppState) => state.users.filter(user => user.role === 'admin')
)

// React.memo with custom comparison
const ExpensiveComponent = React.memo<Props>(
  ({ data, onUpdate }) => {
    // Component implementation
    return <div>{/* ... */}</div>
  },
  (prevProps, nextProps) => {
    // Custom comparison logic
    return (
      prevProps.data.id === nextProps.data.id &&
      prevProps.data.version === nextProps.data.version
    )
  }
)
```

## Testing Patterns

### Type-Safe Testing Utilities

```typescript
// Test utilities with proper typing
type MockedFunction<T extends (...args: any[]) => any> = jest.MockedFunction<T>

interface MockedClass<T> {
  new (...args: any[]): T
  [K in keyof T]: T[K] extends (...args: any[]) => any
    ? MockedFunction<T[K]>
    : T[K]
}

// Factory functions for test data
interface UserFactory {
  build(overrides?: Partial<User>): User
  buildList(count: number, overrides?: Partial<User>): User[]
}

const createUserFactory = (): UserFactory => ({
  build: (overrides = {}) => ({
    id: 'user-123',
    email: 'test@example.com',
    name: 'Test User',
    createdAt: new Date(),
    ...overrides
  }),
  
  buildList: (count, overrides = {}) =>
    Array.from({ length: count }, (_, i) => ({
      id: `user-${i}`,
      email: `user${i}@example.com`,
      name: `User ${i}`,
      createdAt: new Date(),
      ...overrides
    }))
})

// Type-safe mock implementations
const createMockUserService = (): MockedClass<UserService> => {
  const mockService = {
    getUser: jest.fn(),
    createUser: jest.fn(),
    updateUser: jest.fn(),
    deleteUser: jest.fn()
  } as MockedClass<UserService>

  // Set up default implementations
  mockService.getUser.mockResolvedValue(createUserFactory().build())
  mockService.createUser.mockImplementation(async (userData) => 
    createUserFactory().build(userData)
  )

  return mockService
}

// Test helpers for async operations
const waitForNextTick = () => new Promise(resolve => setImmediate(resolve))

const waitForCondition = async (
  condition: () => boolean,
  timeout = 5000
): Promise<void> => {
  const start = Date.now()
  
  while (!condition() && Date.now() - start < timeout) {
    await new Promise(resolve => setTimeout(resolve, 10))
  }
  
  if (!condition()) {
    throw new Error(`Condition not met within ${timeout}ms`)
  }
}
```

### Component Testing Patterns

```typescript
// Testing utilities for React components
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

// Custom render function with providers
interface RenderOptions {
  initialState?: Partial<AppState>
  user?: Partial<User>
}

const renderWithProviders = (
  ui: React.ReactElement,
  options: RenderOptions = {}
) => {
  const { initialState, user } = options
  
  const Wrapper: React.FC<{ children: React.ReactNode }> = ({ children }) => (
    <Provider store={createMockStore(initialState)}>
      <AuthProvider user={user}>
        <Router>
          {children}
        </Router>
      </AuthProvider>
    </Provider>
  )
  
  return {
    user: userEvent.setup(),
    ...render(ui, { wrapper: Wrapper })
  }
}

// Page Object Model for complex components
class UserFormPageObject {
  constructor(private container: HTMLElement) {}

  get nameInput() {
    return screen.getByLabelText(/name/i)
  }

  get emailInput() {
    return screen.getByLabelText(/email/i)
  }

  get submitButton() {
    return screen.getByRole('button', { name: /submit/i })
  }

  async fillForm(userData: Partial<User>) {
    const user = userEvent.setup()
    
    if (userData.name) {
      await user.clear(this.nameInput)
      await user.type(this.nameInput, userData.name)
    }
    
    if (userData.email) {
      await user.clear(this.emailInput)
      await user.type(this.emailInput, userData.email)
    }
  }

  async submit() {
    const user = userEvent.setup()
    await user.click(this.submitButton)
  }
}

// Example test using the page object
describe('UserForm', () => {
  it('should submit form with valid data', async () => {
    const mockOnSubmit = jest.fn()
    const { container } = renderWithProviders(
      <UserForm onSubmit={mockOnSubmit} />
    )
    
    const pageObject = new UserFormPageObject(container)
    
    await pageObject.fillForm({
      name: 'John Doe',
      email: 'john@example.com'
    })
    
    await pageObject.submit()
    
    await waitFor(() => {
      expect(mockOnSubmit).toHaveBeenCalledWith({
        name: 'John Doe',
        email: 'john@example.com'
      })
    })
  })
})
```

## Configuration and Environment

### Type-Safe Configuration

```typescript
// Environment configuration with validation
import { z } from 'zod'

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']),
  PORT: z.coerce.number().default(3000),
  DATABASE_URL: z.string().url(),
  JWT_SECRET: z.string().min(32),
  REDIS_URL: z.string().url().optional(),
  LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']).default('info')
})

type Environment = z.infer<typeof envSchema>

const validateEnvironment = (): Environment => {
  try {
    return envSchema.parse(process.env)
  } catch (error) {
    console.error('Invalid environment configuration:', error)
    process.exit(1)
  }
}

export const env = validateEnvironment()

// Feature flags with type safety
interface FeatureFlags {
  newDashboard: boolean
  advancedAnalytics: boolean
  betaFeatures: boolean
}

const createFeatureFlags = (env: Environment): FeatureFlags => ({
  newDashboard: env.NODE_ENV === 'development' || 
                 process.env.FEATURE_NEW_DASHBOARD === 'true',
  advancedAnalytics: env.NODE_ENV === 'production',
  betaFeatures: env.NODE_ENV !== 'production'
})

export const featureFlags = createFeatureFlags(env)

// Type-safe configuration builder
class ConfigBuilder<T = {}> {
  constructor(private config: T = {} as T) {}

  add<K extends string, V>(key: K, value: V): ConfigBuilder<T & Record<K, V>> {
    return new ConfigBuilder({ ...this.config, [key]: value })
  }

  build(): T {
    return this.config
  }
}

// Usage
const appConfig = new ConfigBuilder()
  .add('database', { url: env.DATABASE_URL, pool: { min: 2, max: 10 } })
  .add('redis', { url: env.REDIS_URL })
  .add('auth', { jwtSecret: env.JWT_SECRET, tokenExpiry: '15m' })
  .build()
```

Remember: TypeScript is not just about adding types to JavaScript—it's about leveraging the type system to catch errors early, improve code maintainability, and enhance developer experience. Always strive for type safety without sacrificing readability or performance.