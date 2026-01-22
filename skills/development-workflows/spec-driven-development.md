# Spec-Driven Development with Kiro

Complete guide to using Kiro's spec system for structured feature development through requirements, design, and task management.

## What is Spec-Driven Development?

Spec-driven development is Kiro's structured approach to building features through three interconnected documents:
- **requirements.md** - Define what needs to be built
- **design.md** - Plan how it will be built  
- **tasks.md** - Break down the implementation steps

This methodology ensures clear communication, proper planning, and systematic execution of complex features.

## The Spec Workflow

```
📋 Requirements → 🎨 Design → ✅ Tasks → 🚀 Implementation

1. Define WHAT (requirements.md)
2. Plan HOW (design.md)  
3. Break down STEPS (tasks.md)
4. Execute with Kiro agents
```

## Requirements Document Structure

### requirements.md Template

```markdown
# Feature Requirements: [Feature Name]

## Overview
Brief description of the feature and its purpose.

## User Stories
Define who needs what and why.

### Primary User Stories
- **As a [user type]**, I want [functionality] so that [benefit]
- **As a [user type]**, I want [functionality] so that [benefit]

### Secondary User Stories  
- **As a [user type]**, I want [functionality] so that [benefit]

## Functional Requirements

### Core Features
1. **[Feature Name]**
   - Description: What this feature does
   - Acceptance Criteria:
     - [ ] Specific, testable requirement
     - [ ] Another specific requirement
   - Priority: High/Medium/Low

2. **[Another Feature]**
   - Description: What this feature does
   - Acceptance Criteria:
     - [ ] Specific requirement
   - Priority: High/Medium/Low

### Integration Requirements
- External APIs or services needed
- Data sources and formats
- Authentication/authorization needs

## Non-Functional Requirements

### Performance
- Response time requirements
- Throughput expectations
- Scalability needs

### Security
- Authentication requirements
- Data protection needs
- Compliance requirements

### Usability
- User experience expectations
- Accessibility requirements
- Browser/device support

## Constraints and Assumptions

### Technical Constraints
- Technology stack limitations
- Infrastructure constraints
- Third-party service limitations

### Business Constraints
- Budget limitations
- Timeline constraints
- Resource availability

### Assumptions
- User behavior assumptions
- Technical assumptions
- Business assumptions

## Success Metrics
- How will success be measured?
- Key performance indicators
- User adoption metrics

## Out of Scope
- What is explicitly NOT included
- Future considerations
- Deferred features

## Dependencies
- Other features or systems this depends on
- External dependencies
- Team dependencies

## Risks and Mitigation
- Technical risks and mitigation strategies
- Business risks and mitigation strategies
- Timeline risks and mitigation strategies
```

### Example Requirements Document

```markdown
# Feature Requirements: User Authentication System

## Overview
Implement a secure user authentication system with registration, login, password reset, and multi-factor authentication capabilities.

## User Stories

### Primary User Stories
- **As a new user**, I want to register an account so that I can access the application
- **As a returning user**, I want to log in securely so that I can access my data
- **As a security-conscious user**, I want MFA options so that my account is protected

### Secondary User Stories
- **As a user**, I want to reset my password so that I can regain access if I forget it
- **As an admin**, I want to manage user accounts so that I can maintain system security

## Functional Requirements

### Core Features
1. **User Registration**
   - Description: Allow new users to create accounts
   - Acceptance Criteria:
     - [ ] User can register with email and password
     - [ ] Email verification is required
     - [ ] Password meets security requirements (8+ chars, mixed case, numbers, symbols)
     - [ ] Duplicate email addresses are rejected
     - [ ] Registration confirmation email is sent
   - Priority: High

2. **User Login**
   - Description: Secure user authentication
   - Acceptance Criteria:
     - [ ] User can log in with email/password
     - [ ] Invalid credentials show appropriate error
     - [ ] Account lockout after 5 failed attempts
     - [ ] Session management with secure tokens
     - [ ] Remember me functionality
   - Priority: High

3. **Multi-Factor Authentication**
   - Description: Optional MFA for enhanced security
   - Acceptance Criteria:
     - [ ] TOTP (Time-based One-Time Password) support
     - [ ] QR code generation for authenticator apps
     - [ ] Backup codes generation
     - [ ] MFA can be enabled/disabled by user
   - Priority: Medium

4. **Password Reset**
   - Description: Self-service password recovery
   - Acceptance Criteria:
     - [ ] Password reset via email link
     - [ ] Reset links expire after 1 hour
     - [ ] Old password is invalidated after reset
     - [ ] Rate limiting on reset requests
   - Priority: High

### Integration Requirements
- Email service for verification and password reset
- Redis for session storage
- Database for user data storage

## Non-Functional Requirements

### Performance
- Login response time < 500ms
- Registration process < 2 seconds
- Support 1000 concurrent users

### Security
- Passwords hashed with bcrypt (cost factor 12)
- JWT tokens with 15-minute expiry
- HTTPS required for all auth endpoints
- OWASP compliance for authentication

### Usability
- Mobile-responsive login/registration forms
- Clear error messages
- Progressive enhancement for MFA setup

## Constraints and Assumptions

### Technical Constraints
- Must integrate with existing Node.js/Express backend
- Must use PostgreSQL database
- Must be compatible with current frontend (React)

### Business Constraints
- Must be completed within 3 weeks
- No budget for external authentication services
- Must comply with GDPR

### Assumptions
- Users have access to email for verification
- Users understand MFA concepts
- Existing database schema can be extended

## Success Metrics
- 95% successful login rate
- < 2% password reset requests per month
- 30% MFA adoption rate within 6 months
- Zero security incidents related to authentication

## Out of Scope
- Social media login (OAuth)
- Single Sign-On (SSO) integration
- Advanced user roles and permissions
- Account deletion functionality

## Dependencies
- Email service configuration
- Redis setup for sessions
- Frontend authentication components
- Database migration system

## Risks and Mitigation
- **Risk**: Security vulnerabilities
  - **Mitigation**: Security audit, penetration testing, code review
- **Risk**: Performance issues under load
  - **Mitigation**: Load testing, database optimization, caching strategy
- **Risk**: Email delivery issues
  - **Mitigation**: Multiple email providers, monitoring, fallback mechanisms
```

## Design Document Structure

### design.md Template

```markdown
# Technical Design: [Feature Name]

## Architecture Overview
High-level system architecture and component interaction.

## System Components

### Frontend Components
- Component hierarchy
- State management approach
- User interface design

### Backend Services
- API endpoints
- Service layer architecture
- Data access patterns

### Database Design
- Schema design
- Relationships
- Indexing strategy

### External Integrations
- Third-party services
- API specifications
- Error handling

## Data Flow Diagrams
Visual representation of data movement through the system.

## API Specifications

### Endpoints
```http
POST /api/auth/register
POST /api/auth/login
POST /api/auth/logout
POST /api/auth/reset-password
GET /api/auth/verify-email
```

### Request/Response Formats
Detailed API contracts with examples.

## Security Considerations
- Authentication mechanisms
- Authorization patterns
- Data protection strategies
- Vulnerability mitigation

## Performance Considerations
- Caching strategies
- Database optimization
- Scalability planning
- Monitoring requirements

## Error Handling
- Error classification
- User-facing error messages
- Logging and monitoring
- Recovery mechanisms

## Testing Strategy
- Unit testing approach
- Integration testing plan
- End-to-end testing scenarios
- Performance testing requirements

## Deployment Strategy
- Environment configuration
- Database migrations
- Feature flags
- Rollback procedures

## Monitoring and Observability
- Metrics to track
- Alerting rules
- Logging requirements
- Health checks
```

### Example Design Document

```markdown
# Technical Design: User Authentication System

## Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   React App     │    │   Express API   │    │   PostgreSQL    │
│                 │    │                 │    │                 │
│ - Login Form    │◄──►│ - Auth Routes   │◄──►│ - Users Table   │
│ - Register Form │    │ - Middleware    │    │ - Sessions      │
│ - MFA Setup     │    │ - Validation    │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │     Redis       │
                       │                 │
                       │ - Sessions      │
                       │ - Rate Limiting │
                       └─────────────────┘
```

## System Components

### Frontend Components

```typescript
// Component hierarchy
AuthProvider
├── LoginForm
├── RegisterForm
├── PasswordResetForm
├── MFASetup
│   ├── QRCodeDisplay
│   ├── BackupCodes
│   └── VerificationInput
└── ProtectedRoute
```

**State Management**: Context API for authentication state
**UI Framework**: React with TypeScript
**Form Handling**: React Hook Form with Zod validation

### Backend Services

```typescript
// Service layer architecture
AuthController
├── AuthService
│   ├── PasswordService
│   ├── TokenService
│   ├── MFAService
│   └── EmailService
├── UserRepository
└── SessionRepository
```

### Database Design

```sql
-- Users table
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  email_verified BOOLEAN DEFAULT FALSE,
  mfa_enabled BOOLEAN DEFAULT FALSE,
  mfa_secret VARCHAR(255),
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Sessions table
CREATE TABLE user_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  token_hash VARCHAR(255) NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Password reset tokens
CREATE TABLE password_reset_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  token_hash VARCHAR(255) NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  used BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_sessions_token ON user_sessions(token_hash);
CREATE INDEX idx_sessions_expires ON user_sessions(expires_at);
CREATE INDEX idx_reset_tokens_hash ON password_reset_tokens(token_hash);
```

## API Specifications

### Authentication Endpoints

```typescript
// POST /api/auth/register
interface RegisterRequest {
  email: string
  password: string
  name: string
}

interface RegisterResponse {
  message: string
  userId: string
}

// POST /api/auth/login
interface LoginRequest {
  email: string
  password: string
  mfaCode?: string
  rememberMe?: boolean
}

interface LoginResponse {
  token: string
  user: {
    id: string
    email: string
    name: string
    mfaEnabled: boolean
  }
  expiresAt: string
}

// POST /api/auth/setup-mfa
interface MFASetupResponse {
  qrCode: string
  secret: string
  backupCodes: string[]
}
```

## Security Considerations

### Password Security
- bcrypt with cost factor 12
- Minimum 8 characters, complexity requirements
- Password history to prevent reuse

### Session Management
- JWT tokens with 15-minute expiry
- Refresh token rotation
- Secure httpOnly cookies for token storage

### Rate Limiting
- Login attempts: 5 per 15 minutes per IP
- Registration: 3 per hour per IP
- Password reset: 3 per hour per email

### MFA Implementation
- TOTP using speakeasy library
- 30-second time window
- Backup codes (10 single-use codes)

## Performance Considerations

### Caching Strategy
- Redis for session storage
- Rate limiting counters in Redis
- MFA secrets cached for verification

### Database Optimization
- Proper indexing on lookup columns
- Connection pooling (max 20 connections)
- Query optimization for user lookups

## Error Handling

### Error Classification
- **ValidationError**: Input validation failures
- **AuthenticationError**: Invalid credentials
- **AuthorizationError**: Insufficient permissions
- **RateLimitError**: Too many requests
- **SystemError**: Internal server errors

### User-Facing Messages
- Generic messages to prevent information leakage
- Specific validation errors for forms
- Clear instructions for error resolution

## Testing Strategy

### Unit Tests
- Password hashing/verification
- Token generation/validation
- MFA code generation/verification
- Input validation

### Integration Tests
- Complete authentication flows
- Database operations
- Email sending
- Rate limiting

### End-to-End Tests
- User registration flow
- Login with MFA
- Password reset process
- Session management

## Deployment Strategy

### Environment Configuration
```bash
# Required environment variables
DATABASE_URL=postgresql://...
REDIS_URL=redis://...
JWT_SECRET=...
EMAIL_SERVICE_API_KEY=...
MFA_ISSUER_NAME=MyApp
```

### Database Migrations
- Versioned migration scripts
- Rollback procedures
- Data seeding for development

### Feature Flags
- MFA_ENABLED: Toggle MFA functionality
- EMAIL_VERIFICATION_REQUIRED: Toggle email verification
- RATE_LIMITING_ENABLED: Toggle rate limiting

## Monitoring and Observability

### Metrics to Track
- Authentication success/failure rates
- MFA adoption rate
- Password reset frequency
- Session duration
- API response times

### Alerting Rules
- High authentication failure rate (>10% in 5 minutes)
- Database connection issues
- Email service failures
- Unusual login patterns

### Health Checks
- Database connectivity
- Redis connectivity
- Email service availability
- JWT secret validation
```

## Tasks Document Structure

### tasks.md Template

```markdown
# Implementation Tasks: [Feature Name]

## Task Breakdown

### Phase 1: Foundation
- [ ] **Task 1.1**: Setup project structure
  - **Estimate**: 2 hours
  - **Assignee**: Developer
  - **Dependencies**: None
  - **Acceptance Criteria**: 
    - Project structure created
    - Dependencies installed
    - Basic configuration complete

### Phase 2: Core Implementation
- [ ] **Task 2.1**: Implement core feature
  - **Estimate**: 8 hours
  - **Assignee**: Developer
  - **Dependencies**: Task 1.1
  - **Acceptance Criteria**:
    - Feature works as specified
    - Unit tests pass
    - Code review complete

### Phase 3: Integration & Testing
- [ ] **Task 3.1**: Integration testing
  - **Estimate**: 4 hours
  - **Assignee**: QA Engineer
  - **Dependencies**: Task 2.1
  - **Acceptance Criteria**:
    - All integration tests pass
    - Performance requirements met

### Phase 4: Deployment
- [ ] **Task 4.1**: Production deployment
  - **Estimate**: 2 hours
  - **Assignee**: DevOps
  - **Dependencies**: Task 3.1
  - **Acceptance Criteria**:
    - Successfully deployed to production
    - Monitoring configured
    - Rollback plan tested

## Timeline
- **Total Estimate**: 16 hours
- **Start Date**: [Date]
- **Target Completion**: [Date]

## Risk Mitigation
- **Risk**: Technical complexity
  - **Mitigation**: Proof of concept, expert consultation
- **Risk**: Timeline pressure
  - **Mitigation**: Prioritize core features, defer nice-to-haves

## Definition of Done
- [ ] All acceptance criteria met
- [ ] Code reviewed and approved
- [ ] Tests written and passing
- [ ] Documentation updated
- [ ] Deployed to production
- [ ] Monitoring configured
```

### Example Tasks Document

```markdown
# Implementation Tasks: User Authentication System

## Task Breakdown

### Phase 1: Database & Infrastructure (Week 1)

- [ ] **Task 1.1**: Database schema setup
  - **Estimate**: 4 hours
  - **Assignee**: Backend Developer
  - **Dependencies**: None
  - **Acceptance Criteria**:
    - Users table created with proper constraints
    - Sessions table implemented
    - Password reset tokens table added
    - Proper indexes created
    - Migration scripts written

- [ ] **Task 1.2**: Redis session store configuration
  - **Estimate**: 2 hours
  - **Assignee**: DevOps Engineer
  - **Dependencies**: None
  - **Acceptance Criteria**:
    - Redis instance configured
    - Connection pooling setup
    - Session serialization working
    - TTL configuration correct

- [ ] **Task 1.3**: Email service integration
  - **Estimate**: 3 hours
  - **Assignee**: Backend Developer
  - **Dependencies**: None
  - **Acceptance Criteria**:
    - Email service configured (SendGrid/SES)
    - Template system setup
    - Error handling implemented
    - Rate limiting configured

### Phase 2: Backend Authentication (Week 1-2)

- [ ] **Task 2.1**: User registration endpoint
  - **Estimate**: 6 hours
  - **Assignee**: Backend Developer
  - **Dependencies**: Task 1.1, 1.3
  - **Acceptance Criteria**:
    - POST /api/auth/register endpoint
    - Input validation (email, password strength)
    - Password hashing with bcrypt
    - Email verification flow
    - Duplicate email handling
    - Unit tests written

- [ ] **Task 2.2**: User login endpoint
  - **Estimate**: 6 hours
  - **Assignee**: Backend Developer
  - **Dependencies**: Task 1.1, 1.2
  - **Acceptance Criteria**:
    - POST /api/auth/login endpoint
    - Credential verification
    - JWT token generation
    - Session management
    - Rate limiting (5 attempts per 15 min)
    - Account lockout mechanism
    - Unit tests written

- [ ] **Task 2.3**: Password reset functionality
  - **Estimate**: 5 hours
  - **Assignee**: Backend Developer
  - **Dependencies**: Task 1.1, 1.3
  - **Acceptance Criteria**:
    - POST /api/auth/reset-password endpoint
    - GET /api/auth/reset-password/:token endpoint
    - Secure token generation
    - Email sending with reset link
    - Token expiration (1 hour)
    - Rate limiting on requests
    - Unit tests written

- [ ] **Task 2.4**: Multi-factor authentication
  - **Estimate**: 8 hours
  - **Assignee**: Backend Developer
  - **Dependencies**: Task 2.2
  - **Acceptance Criteria**:
    - MFA setup endpoint
    - TOTP implementation with speakeasy
    - QR code generation
    - Backup codes generation
    - MFA verification in login flow
    - Enable/disable MFA endpoints
    - Unit tests written

### Phase 3: Frontend Implementation (Week 2)

- [ ] **Task 3.1**: Authentication context and hooks
  - **Estimate**: 4 hours
  - **Assignee**: Frontend Developer
  - **Dependencies**: None
  - **Acceptance Criteria**:
    - AuthContext with React Context API
    - useAuth hook for components
    - Token storage in httpOnly cookies
    - Automatic token refresh
    - Logout functionality
    - TypeScript interfaces defined

- [ ] **Task 3.2**: Registration form component
  - **Estimate**: 5 hours
  - **Assignee**: Frontend Developer
  - **Dependencies**: Task 3.1, 2.1
  - **Acceptance Criteria**:
    - Responsive registration form
    - Real-time validation with Zod
    - Password strength indicator
    - Error handling and display
    - Success state with email verification notice
    - Accessibility compliance
    - Unit tests with React Testing Library

- [ ] **Task 3.3**: Login form component
  - **Estimate**: 4 hours
  - **Assignee**: Frontend Developer
  - **Dependencies**: Task 3.1, 2.2
  - **Acceptance Criteria**:
    - Responsive login form
    - Form validation
    - Remember me checkbox
    - Error handling for various scenarios
    - Loading states
    - Redirect after successful login
    - Unit tests written

- [ ] **Task 3.4**: MFA setup and verification
  - **Estimate**: 6 hours
  - **Assignee**: Frontend Developer
  - **Dependencies**: Task 3.1, 2.4
  - **Acceptance Criteria**:
    - MFA setup wizard component
    - QR code display for authenticator apps
    - Backup codes display and download
    - MFA verification input component
    - Integration with login flow
    - Enable/disable MFA in user settings
    - Unit tests written

- [ ] **Task 3.5**: Password reset flow
  - **Estimate**: 3 hours
  - **Assignee**: Frontend Developer
  - **Dependencies**: Task 3.1, 2.3
  - **Acceptance Criteria**:
    - Password reset request form
    - Password reset confirmation page
    - New password form with validation
    - Success and error states
    - Link expiration handling
    - Unit tests written

### Phase 4: Integration & Testing (Week 3)

- [ ] **Task 4.1**: End-to-end testing
  - **Estimate**: 8 hours
  - **Assignee**: QA Engineer
  - **Dependencies**: All Phase 2 & 3 tasks
  - **Acceptance Criteria**:
    - Complete user registration flow test
    - Login with and without MFA test
    - Password reset flow test
    - Account lockout scenario test
    - Email verification test
    - Cross-browser compatibility test
    - Mobile responsiveness test

- [ ] **Task 4.2**: Security testing
  - **Estimate**: 6 hours
  - **Assignee**: Security Engineer
  - **Dependencies**: All Phase 2 tasks
  - **Acceptance Criteria**:
    - Penetration testing completed
    - SQL injection testing
    - XSS vulnerability testing
    - CSRF protection verification
    - Rate limiting validation
    - Password security audit
    - Security report generated

- [ ] **Task 4.3**: Performance testing
  - **Estimate**: 4 hours
  - **Assignee**: Performance Engineer
  - **Dependencies**: All Phase 2 tasks
  - **Acceptance Criteria**:
    - Load testing with 1000 concurrent users
    - Login response time < 500ms verified
    - Database query optimization
    - Memory usage profiling
    - Performance report generated

### Phase 5: Deployment & Monitoring (Week 3)

- [ ] **Task 5.1**: Production deployment
  - **Estimate**: 4 hours
  - **Assignee**: DevOps Engineer
  - **Dependencies**: Task 4.1, 4.2, 4.3
  - **Acceptance Criteria**:
    - Environment variables configured
    - Database migrations executed
    - SSL certificates configured
    - Load balancer configuration
    - Health checks implemented
    - Rollback procedure tested

- [ ] **Task 5.2**: Monitoring and alerting setup
  - **Estimate**: 3 hours
  - **Assignee**: DevOps Engineer
  - **Dependencies**: Task 5.1
  - **Acceptance Criteria**:
    - Authentication metrics dashboard
    - Error rate alerting configured
    - Performance monitoring setup
    - Log aggregation configured
    - Uptime monitoring enabled
    - Alert notification channels setup

- [ ] **Task 5.3**: Documentation and training
  - **Estimate**: 4 hours
  - **Assignee**: Technical Writer
  - **Dependencies**: Task 5.1
  - **Acceptance Criteria**:
    - API documentation updated
    - User guide for MFA setup
    - Admin guide for user management
    - Troubleshooting guide
    - Security best practices document
    - Team training session conducted

## Timeline Summary
- **Phase 1**: 9 hours (Week 1)
- **Phase 2**: 25 hours (Week 1-2)
- **Phase 3**: 22 hours (Week 2)
- **Phase 4**: 18 hours (Week 3)
- **Phase 5**: 11 hours (Week 3)
- **Total Estimate**: 85 hours (~3 weeks with 2 developers)

## Risk Mitigation

### Technical Risks
- **Risk**: MFA implementation complexity
  - **Mitigation**: Use proven library (speakeasy), create prototype first
  - **Contingency**: Defer MFA to Phase 2 if needed

- **Risk**: Email delivery issues
  - **Mitigation**: Use reliable service (SendGrid), implement monitoring
  - **Contingency**: Have backup email service configured

- **Risk**: Performance under load
  - **Mitigation**: Early performance testing, database optimization
  - **Contingency**: Implement caching layer if needed

### Timeline Risks
- **Risk**: Frontend complexity underestimated
  - **Mitigation**: Daily standups, early integration testing
  - **Contingency**: Simplify UI, defer advanced features

- **Risk**: Security testing reveals major issues
  - **Mitigation**: Security review during development
  - **Contingency**: Additional sprint for security fixes

## Definition of Done
- [ ] All acceptance criteria met for each task
- [ ] Code reviewed and approved by senior developer
- [ ] Unit tests written with >80% coverage
- [ ] Integration tests passing
- [ ] Security review completed
- [ ] Performance requirements met
- [ ] Documentation updated
- [ ] Deployed to production successfully
- [ ] Monitoring and alerting configured
- [ ] Stakeholder sign-off received
```

## Using Specs with Kiro Agents

### Agent Integration Workflow

```markdown
# Working with Kiro Agents on Specs

## 1. Requirements Phase
"Use the architect agent to review these requirements and suggest improvements"
"Have the security-auditor agent validate the security requirements"
"Ask the performance-optimizer agent to review the performance requirements"

## 2. Design Phase  
"Use the architect agent to create the technical design based on these requirements"
"Have the code-reviewer agent review the proposed architecture for best practices"
"Ask the test-engineer agent to define the testing strategy"

## 3. Implementation Phase
"Use the test-engineer agent to implement TDD for each task"
"Have the code-reviewer agent review each completed task"
"Ask the devops-specialist agent to handle deployment tasks"

## 4. Validation Phase
"Use the debug-detective agent to investigate any issues found"
"Have the performance-optimizer agent validate performance requirements"
"Ask the security-auditor agent to perform final security review"
```

### Spec File References

Specs support file references using the `#[[file:path]]` syntax:

```markdown
# Design Document

## API Specification
See the complete API specification: #[[file:api-spec.yaml]]

## Database Schema
Reference the database schema: #[[file:schema.sql]]

## Frontend Components
Component specifications: #[[file:components.md]]
```

## Best Practices

### Requirements Best Practices
1. **Be Specific**: Use measurable acceptance criteria
2. **Include Context**: Explain the "why" behind each requirement
3. **Consider Edge Cases**: Think about error scenarios and edge cases
4. **Prioritize**: Clearly mark what's essential vs. nice-to-have
5. **Validate Early**: Review requirements with stakeholders before design

### Design Best Practices
1. **Start Simple**: Begin with the simplest solution that meets requirements
2. **Plan for Scale**: Consider future growth and extensibility
3. **Security First**: Build security considerations into the design
4. **Document Decisions**: Explain why specific approaches were chosen
5. **Review Architecture**: Have experienced developers review the design

### Tasks Best Practices
1. **Right-Size Tasks**: Keep tasks to 4-8 hours each
2. **Clear Dependencies**: Explicitly state what each task depends on
3. **Measurable Outcomes**: Define clear acceptance criteria
4. **Risk Planning**: Identify risks and mitigation strategies
5. **Regular Updates**: Keep task status current and communicate blockers

Remember: Spec-driven development with Kiro creates a structured approach to feature development that ensures clear communication, proper planning, and systematic execution. Use the three-document approach (requirements → design → tasks) to break down complex features into manageable, well-defined work items that can be efficiently executed with Kiro's AI agents.