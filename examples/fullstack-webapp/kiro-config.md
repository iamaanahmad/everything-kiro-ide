# Full-Stack Web Application - Kiro Configuration

This example demonstrates a complete Kiro setup for a modern full-stack web application using React, Node.js, PostgreSQL, and Redis.

## Project Structure

```
my-webapp/
├── .kiro/
│   ├── settings/
│   │   └── mcp.json              # MCP server configurations
│   ├── hooks/                    # Project-specific hooks (one v1 JSON file per hook)
│   └── steering/
│       ├── project-context.md    # Project-specific context
│       └── api-standards.md      # API design standards
├── frontend/                     # React TypeScript frontend
├── backend/                      # Node.js Express API
├── database/                     # PostgreSQL migrations and seeds
├── docker-compose.yml            # Development environment
└── README.md
```

## MCP Configuration

### .kiro/settings/mcp.json
```json
{
  "mcpServers": {
    "postgres": {
      "command": "uvx",
      "args": ["mcp-server-postgres"],
      "env": {
        "POSTGRES_CONNECTION_STRING": "postgresql://webapp_user:webapp_pass@localhost:5432/webapp_db"
      },
      "disabled": false,
      "autoApprove": ["list_tables", "describe_table", "query"]
    },
    "redis": {
      "command": "uvx",
      "args": ["mcp-server-redis"],
      "env": {
        "REDIS_URL": "redis://localhost:6379"
      },
      "disabled": false,
      "autoApprove": ["get", "keys", "info"]
    },
    "github": {
      "command": "uvx",
      "args": ["mcp-server-github"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_your_token_here"
      },
      "disabled": false,
      "autoApprove": ["list_repositories", "get_repository", "create_issue"]
    },
    "docker": {
      "command": "uvx",
      "args": ["mcp-server-docker"],
      "disabled": false,
      "autoApprove": ["list_containers", "container_status", "list_images"]
    },
    "filesystem": {
      "command": "uvx",
      "args": ["mcp-server-filesystem", "--base-directory", "."],
      "disabled": false,
      "autoApprove": ["read_file", "list_directory", "search_files"]
    },
    "git": {
      "command": "uvx",
      "args": ["mcp-server-git"],
      "disabled": false,
      "autoApprove": ["git_status", "git_log", "git_diff"]
    },
    "vercel": {
      "command": "uvx",
      "args": ["mcp-server-vercel"],
      "env": {
        "VERCEL_TOKEN": "your_vercel_token_here"
      },
      "disabled": true,
      "autoApprove": ["list_projects", "get_deployments"]
    }
  }
}
```

## Project-Specific Hooks

Real hooks live under `.kiro/hooks/`, one JSON file per hook (or a few grouped together), using the v1 schema — not a single `hooks.json` array of legacy objects. Example files for this project:

### .kiro/hooks/frontend-build-check.json
```json
{
  "version": "v1",
  "hooks": [{
    "name": "frontend-build-check",
    "trigger": "PostFileSave",
    "matcher": "frontend/src/.*\\.tsx?$",
    "action": { "type": "command", "command": "cd frontend && npm run type-check && npm run lint" },
    "timeout": 60
  }]
}
```

### .kiro/hooks/backend-test-on-change.json
```json
{
  "version": "v1",
  "hooks": [{
    "name": "backend-test-on-change",
    "trigger": "PostFileSave",
    "matcher": "backend/src/.*\\.ts$",
    "action": { "type": "command", "command": "cd backend && npm test -- --findRelatedTests \"$FILE_PATH\" --passWithNoTests" },
    "timeout": 60
  }]
}
```

### .kiro/hooks/database-migration-review.json
```json
{
  "version": "v1",
  "hooks": [{
    "name": "database-migration-review",
    "trigger": "PostFileCreate",
    "matcher": "database/migrations/.*\\.sql$",
    "action": {
      "type": "agent",
      "prompt": "A new database migration was created. Use the architect agent to review it for data safety and rollback strategy, performance impact on large tables, index optimization, and breaking changes."
    }
  }]
}
```

### .kiro/hooks/api-documentation-update.json
```json
{
  "version": "v1",
  "hooks": [{
    "name": "api-documentation-update",
    "trigger": "PostFileSave",
    "matcher": "backend/src/(routes|controllers)/.*\\.ts$",
    "action": {
      "type": "agent",
      "prompt": "API endpoints were modified. Use the documentation-writer agent to update the OpenAPI spec, README API docs, and example requests/responses."
    }
  }]
}
```

### .kiro/hooks/security-review-auth.json
```json
{
  "version": "v1",
  "hooks": [{
    "name": "security-review-auth",
    "trigger": "PostFileSave",
    "matcher": "backend/src/(auth|middleware)/.*\\.ts$",
    "action": {
      "type": "agent",
      "prompt": "Authentication code was modified. Use the security-auditor agent to review JWT handling, password hashing, session management, authorization logic, and potential vulnerabilities."
    }
  }]
}
```

### .kiro/hooks/e2e-test-reminder.json
```json
{
  "version": "v1",
  "hooks": [{
    "name": "e2e-test-reminder",
    "trigger": "PostFileSave",
    "matcher": "frontend/src/(pages|components)/.*\\.tsx$",
    "action": {
      "type": "agent",
      "prompt": "UI components were modified. Use the test-engineer agent to review affected E2E tests, update selectors if structure changed, and confirm accessibility testing is included."
    }
  }]
}
```

### .kiro/hooks/docker-config-validation.json
```json
{
  "version": "v1",
  "hooks": [{
    "name": "docker-config-validation",
    "trigger": "PostFileSave",
    "matcher": "(Dockerfile|docker-compose\\.ya?ml|\\.dockerignore)$",
    "action": { "type": "command", "command": "docker-compose config" },
    "timeout": 15
  }]
}
```

### .kiro/hooks/env-security-check.json
```json
{
  "version": "v1",
  "hooks": [{
    "name": "env-security-check",
    "trigger": "PostFileSave",
    "matcher": "\\.env(\\..*)?$",
    "action": {
      "type": "agent",
      "prompt": "Environment configuration changed. Check for hardcoded secrets, confirm sensitive values use env vars, and confirm .env.example is in sync."
    }
  }]
}
```

## Steering Configuration

### .kiro/steering/project-context.md
```markdown
---
inclusion: always
---

# My Web App - Project Context

## Project Overview
A modern full-stack web application for [describe your app's purpose]. Built with React, Node.js, PostgreSQL, and Redis.

## Architecture
- **Frontend**: React 18 with TypeScript, Vite, TailwindCSS
- **Backend**: Node.js with Express, TypeScript, Prisma ORM
- **Database**: PostgreSQL 15 with Redis for caching
- **Authentication**: JWT with refresh tokens
- **Deployment**: Docker containers on Vercel/Railway

## Key Features
- User authentication and authorization
- Real-time notifications (WebSocket)
- File upload and processing
- Email notifications
- Admin dashboard
- API rate limiting and caching

## Development Workflow
1. Use TDD for all new features
2. Write integration tests for API endpoints
3. Use Playwright for E2E testing
4. Code review required for all PRs
5. Automated deployment on merge to main

## Database Schema
- **users**: User accounts and profiles
- **posts**: User-generated content
- **comments**: Post comments and replies
- **notifications**: Real-time user notifications
- **sessions**: Active user sessions

## API Standards
- RESTful endpoints with consistent naming
- JSON responses with standard error format
- Pagination for list endpoints
- Rate limiting: 100 requests/minute per user
- API versioning: /api/v1/

## Security Requirements
- All passwords hashed with bcrypt (12 rounds)
- JWT tokens expire in 15 minutes
- Refresh tokens expire in 7 days
- CORS configured for production domains only
- Input validation on all endpoints
- SQL injection prevention with parameterized queries

## Performance Targets
- Page load time < 2 seconds
- API response time < 500ms
- Database queries < 100ms
- 99.9% uptime
- Support 1000 concurrent users

## Monitoring and Logging
- Application logs with structured JSON
- Error tracking with Sentry
- Performance monitoring with New Relic
- Database query monitoring
- Real-time alerts for critical errors
```

### .kiro/steering/api-standards.md
```markdown
---
inclusion: fileMatch
fileMatchPattern: "backend/**/*.ts"
---

# API Design Standards

## Endpoint Naming
- Use nouns for resources: `/api/v1/users`, `/api/v1/posts`
- Use HTTP methods for actions: GET, POST, PUT, DELETE
- Use kebab-case for multi-word resources: `/api/v1/user-profiles`

## Request/Response Format
```typescript
// Standard success response
{
  "success": true,
  "data": { ... },
  "meta": {
    "timestamp": "2024-01-15T10:30:00Z",
    "requestId": "req_123456"
  }
}

// Standard error response
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input data",
    "details": [
      {
        "field": "email",
        "message": "Invalid email format"
      }
    ]
  },
  "meta": {
    "timestamp": "2024-01-15T10:30:00Z",
    "requestId": "req_123456"
  }
}
```

## Status Codes
- 200: Success
- 201: Created
- 400: Bad Request (validation errors)
- 401: Unauthorized
- 403: Forbidden
- 404: Not Found
- 409: Conflict (duplicate resource)
- 422: Unprocessable Entity
- 500: Internal Server Error

## Pagination
```typescript
// Request
GET /api/v1/posts?page=2&limit=20&sort=createdAt&order=desc

// Response
{
  "success": true,
  "data": [...],
  "meta": {
    "pagination": {
      "page": 2,
      "limit": 20,
      "total": 150,
      "pages": 8,
      "hasNext": true,
      "hasPrev": true
    }
  }
}
```

## Authentication
- Use Bearer tokens: `Authorization: Bearer <jwt_token>`
- Include user context in all authenticated endpoints
- Implement refresh token rotation

## Validation
- Validate all input data
- Use Zod schemas for type-safe validation
- Return detailed validation errors
- Sanitize output data (no sensitive fields)

## Rate Limiting
- 100 requests per minute per user
- 1000 requests per minute per IP
- Different limits for different endpoint types
- Include rate limit headers in responses
```

## Development Commands

### Package.json Scripts
```json
{
  "scripts": {
    "dev": "concurrently \"npm run dev:backend\" \"npm run dev:frontend\"",
    "dev:backend": "cd backend && npm run dev",
    "dev:frontend": "cd frontend && npm run dev",
    "build": "npm run build:backend && npm run build:frontend",
    "build:backend": "cd backend && npm run build",
    "build:frontend": "cd frontend && npm run build",
    "test": "npm run test:backend && npm run test:frontend",
    "test:backend": "cd backend && npm test",
    "test:frontend": "cd frontend && npm test",
    "test:e2e": "cd e2e && npx playwright test",
    "lint": "npm run lint:backend && npm run lint:frontend",
    "lint:backend": "cd backend && npm run lint",
    "lint:frontend": "cd frontend && npm run lint",
    "db:migrate": "cd backend && npx prisma migrate dev",
    "db:seed": "cd backend && npx prisma db seed",
    "db:reset": "cd backend && npx prisma migrate reset",
    "docker:up": "docker-compose up -d",
    "docker:down": "docker-compose down",
    "docker:logs": "docker-compose logs -f"
  }
}
```

## Docker Configuration

### docker-compose.yml
```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: webapp_db
      POSTGRES_USER: webapp_user
      POSTGRES_PASSWORD: webapp_pass
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./database/init:/docker-entrypoint-initdb.d

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

  backend:
    build: ./backend
    ports:
      - "3001:3001"
    environment:
      - NODE_ENV=development
      - DATABASE_URL=postgresql://webapp_user:webapp_pass@postgres:5432/webapp_db
      - REDIS_URL=redis://redis:6379
      - JWT_SECRET=your_jwt_secret_here
    depends_on:
      - postgres
      - redis
    volumes:
      - ./backend:/app
      - /app/node_modules

  frontend:
    build: ./frontend
    ports:
      - "3000:3000"
    environment:
      - VITE_API_URL=http://localhost:3001/api/v1
    volumes:
      - ./frontend:/app
      - /app/node_modules

volumes:
  postgres_data:
  redis_data:
```

## Usage Examples

### Starting Development
```bash
# Start all services
npm run docker:up

# Run database migrations
npm run db:migrate

# Seed the database
npm run db:seed

# Start development servers
npm run dev
```

### Working with Kiro Agents
```
# Architecture planning
"Use the architect agent to design a new notification system that supports real-time WebSocket notifications and email fallbacks"

# Code review
"Use the code-reviewer agent to review the authentication middleware for security vulnerabilities and performance issues"

# Testing
"Use the test-engineer agent to create comprehensive E2E tests for the user registration and login flow"

# Database design
"Use the architect agent to design database tables for a comment system with nested replies and voting"
```

### Common Development Tasks
```bash
# Add new API endpoint
"Create a new API endpoint for user profile management with full CRUD operations, validation, and tests"

# Database changes
"Add a new table for user notifications with appropriate indexes and foreign key constraints"

# Frontend component
"Create a reusable React component for displaying user avatars with loading states and error handling"

# Security review
"Review the password reset functionality for security vulnerabilities and implement rate limiting"
```

This configuration provides a solid foundation for full-stack web application development with Kiro, including automated testing, code quality checks, security reviews, and comprehensive development workflows.