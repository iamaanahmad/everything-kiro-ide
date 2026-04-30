# Everything Kiro

**The complete collection of Kiro configurations from real-world production use.**

Production-ready agents, skills, hooks, steering files, specs, and MCP integrations evolved from intensive daily development. Unlock the full potential of Kiro IDE with battle-tested patterns.

---

## The Guides

This repo is the raw code only. For comprehensive guides, see:

### **[Kiro Documentation](https://docs.kiro.dev)** (if available)

The foundation - what each config type does, how to structure your setup, context window management, and the philosophy behind these configs.

---

## What's Inside

This repo is organized for **Kiro IDE** - install components directly or copy manually.

```
everything-kiro/
├── .kiro/                    # Kiro-specific configurations
│   ├── settings/
│   │   └── mcp.json         # MCP server configurations
│   └── steering/            # Always-active context and guidelines
│       ├── coding-standards.md
│       ├── security-rules.md
│       └── project-patterns.md
│
├── agents/                  # Specialized sub-agents for delegation
│   ├── architect.md         # System design and planning
│   ├── code-reviewer.md     # Quality and security review
│   ├── test-engineer.md     # TDD and testing workflows
│   ├── devops-specialist.md # Deployment and infrastructure
│   ├── debug-detective.md   # Bug investigation and fixing
│   ├── performance-optimizer.md
│   ├── security-auditor.md
│   └── documentation-writer.md
│
├── powers/                  # Kiro Powers (packaged capabilities)
│   ├── README.md            # Powers documentation
│   ├── development-power/   # Development workflows power
│   ├── devops-power/        # DevOps and deployment power
│   └── database-power/      # Database management power
│
├── skills/                  # Reusable workflow patterns
│   ├── development-workflows/
│   │   ├── spec-driven-development.md
│   │   └── tdd-cycle.md
│   ├── language-patterns/
│   │   ├── typescript-best-practices.md
│   │   ├── python-conventions.md
│   │   └── react-patterns.md
│   └── infrastructure/
│       ├── docker-workflows.md
│       ├── ci-cd-patterns.md
│       └── monitoring-setup.md
│
├── hooks/                   # Event-driven automations
│   └── file-watchers.json   # File change automation
│
├── specs/                   # Spec-driven development templates
│   ├── feature-template.md
│   ├── api-endpoint-template.md
│   └── refactor-template.md
│
└── examples/               # Example projects and configurations
    └── fullstack-webapp/   # Complete web application setup
```

---

## Key Concepts

### Agents

Subagents handle delegated tasks with limited scope. Kiro can invoke agents proactively based on context.

**Example:**
```markdown
---
name: code-reviewer
description: Reviews code for quality, security, and maintainability
tools: Read, Grep, Glob, Bash
---

You are a senior code reviewer...
```

**Available Agents:**
- **architect** - System design and architecture decisions
- **code-reviewer** - Quality and security review
- **test-engineer** - TDD and testing workflows
- **devops-specialist** - Deployment and infrastructure
- **debug-detective** - Bug investigation and fixing
- **performance-optimizer** - Performance analysis and optimization
- **security-auditor** - Security vulnerability detection
- **documentation-writer** - Documentation generation and updates

### Steering Files

Steering files provide always-active context to guide Kiro's behavior. They're automatically loaded from `.kiro/steering/`.

**Example:**
```markdown
# Coding Standards

## Naming Conventions
- Use camelCase for variables
- Use PascalCase for classes
- Use UPPER_SNAKE_CASE for constants

## File Organization
- Maximum file size: 800 lines
- One component per file
- Group related files by feature
```

**Inclusion Types:**
- **Always included** (default) - Active in all conversations
- **Conditional** - Included when specific files are read
- **Manual** - User provides via context key (#)

### Hooks

Hooks fire on IDE events and can trigger agent actions or commands.

**Event Types:**
- `fileEdited` - When a file is saved
- `fileCreated` - When a new file is created
- `fileDeleted` - When a file is deleted
- `userTriggered` - Manual trigger by user
- `promptSubmit` - When a message is sent
- `agentStop` - When agent execution completes
- `preToolUse` - Before a tool is executed
- `postToolUse` - After a tool is executed
- `preTaskExecution` - Before a spec task starts
- `postTaskExecution` - After a spec task completes

**Hook Actions:**
- `askAgent` - Send a message to the agent
- `runCommand` - Execute a shell command

**Example:**
```json
{
  "name": "Lint on Save",
  "eventType": "fileEdited",
  "filePatterns": ["*.ts", "*.tsx"],
  "hookAction": "runCommand",
  "command": "npm run lint"
}
```

### Specs

Specs are a structured way of building and documenting features. A spec formalizes the design and implementation process.

**Spec Workflow:**
1. **Requirements** - Define what needs to be built
2. **Design** - Plan the implementation approach
3. **Tasks** - Break down into actionable tasks
4. **Implementation** - Agent works through tasks
5. **Verification** - Test and validate

**Spec Features:**
- Incremental development of complex features
- Control and feedback at each step
- File references via `#[[file:path/to/file]]`
- Task status tracking (pending, in_progress, completed)

### Skills

Skills are workflow definitions that can be invoked by commands or agents.

**Example:**
```markdown
# TDD Workflow

1. Define interfaces first
2. Write failing tests (RED)
3. Implement minimal code (GREEN)
4. Refactor (IMPROVE)
5. Verify 80%+ coverage
```

### MCP (Model Context Protocol)

MCP servers provide external integrations (GitHub, databases, APIs).

**Example Configuration:**
```json
{
  "mcpServers": {
    "github": {
      "command": "uvx",
      "args": ["mcp-server-github"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "your_token_here"
      }
    }
  }
}
```

**Important:** Keep under 10 MCPs enabled to preserve context window.

### Powers

**NEW:** Powers package documentation, workflow guides, and MCP servers into reusable units.

**What are Powers:**
- Package capabilities for easy distribution
- Include documentation (POWER.md)
- Optional steering files for workflows
- Optional MCP server configurations
- Shareable and reusable across projects

**Power Actions:**
- `list` - See all installed powers
- `activate` - Load power documentation and tools
- `use` - Execute power tools
- `readSteering` - Get detailed workflow guides
- `configure` - Open powers management panel

**Example:**
```
User: Activate development power

Kiro: [Loads development-power]
Available workflows:
- Code review process
- TDD methodology
- Debugging strategies
- Quality assurance

User: Read the code review guide

Kiro: [Shows code-review-process.md]
```

**Available Powers in this repo:**
- **development-power** - Development workflows (code review, TDD, debugging)
- **devops-power** - DevOps and deployment workflows
- **database-power** - Database management and queries

See [powers/README.md](powers/README.md) for complete documentation.

---

## Installation

### Option 1: Copy to Workspace

```bash
# Clone the repository
git clone https://github.com/yourusername/everything-kiro.git

# Copy to your workspace
cp -r everything-kiro/.kiro .kiro
cp -r everything-kiro/agents agents
cp -r everything-kiro/skills skills
cp -r everything-kiro/hooks hooks
```

### Option 2: User-Level Installation

```bash
# Copy to user-level Kiro directory
cp -r everything-kiro/.kiro ~/.kiro
cp -r everything-kiro/agents ~/.kiro/agents
cp -r everything-kiro/skills ~/.kiro/skills
```

### Configure MCP Servers

Edit `.kiro/settings/mcp.json` and replace placeholders with your actual API keys:

```json
{
  "mcpServers": {
    "github": {
      "command": "uvx",
      "args": ["mcp-server-github"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "YOUR_TOKEN_HERE"
      }
    }
  }
}
```

**Important:** Never commit files with real API keys!

---

## Usage Examples

### Using Agents

```
User: Review this code for security issues

Kiro: [Invokes security-auditor agent]

Security Auditor:
# Security Review Report

## Critical Issues
- [CRITICAL] Hardcoded API key in config.ts:42
- [HIGH] SQL injection vulnerability in user-service.ts:156

## Recommendations
...
```

### Using Hooks

```json
{
  "name": "TDD Enforcer",
  "eventType": "fileEdited",
  "filePatterns": ["src/**/*.ts"],
  "hookAction": "askAgent",
  "outputPrompt": "Ensure this file has corresponding tests with 80%+ coverage"
}
```

### Using Specs

```
User: Create a spec for user authentication feature

Kiro: [Creates spec with requirements, design, and tasks]

Spec: User Authentication
├── Requirements
│   ├── Email/password login
│   ├── JWT token generation
│   └── Password reset flow
├── Design
│   ├── Database schema
│   ├── API endpoints
│   └── Security considerations
└── Tasks
    ├── [ ] Create user model
    ├── [ ] Implement login endpoint
    ├── [ ] Add JWT middleware
    └── [ ] Write tests
```

### Using Steering Files

Steering files are automatically active. They guide Kiro's behavior without explicit invocation.

```markdown
# .kiro/steering/security-rules.md

## Security Requirements

- Never hardcode secrets
- Always validate user input
- Use parameterized queries
- Implement rate limiting
```

---

## Key Features

### 🤖 Intelligent Agents (8 total)

Specialized agents for different aspects of development:
- System architecture and design
- Code quality and security review
- Test-driven development
- DevOps and deployment
- Debugging and troubleshooting
- Performance optimization
- Security auditing
- Documentation generation

### ⚡ Smart Hooks

Event-driven automation:
- Auto-format code on save
- Run tests on file changes
- Security scans on dependency updates
- Documentation updates on API changes
- Database migration reviews

### 📋 Spec-Driven Development

Structured feature development:
- Requirements documentation
- Design planning
- Task breakdown
- Implementation tracking
- Verification steps

### 🎯 Steering Rules

Always-active context:
- Coding standards
- Security requirements
- Project patterns
- Team conventions

### 🔌 MCP Integrations

External service connections:
- GitHub (PRs, issues, repos)
- Databases (PostgreSQL, MongoDB, Redis)
- Cloud services (AWS, GCP, Azure)
- Development tools (Jira, Slack, etc.)

### ⚡ Powers (NEW!)

Packaged capabilities for easy distribution:
- **development-power** - Code review, TDD, debugging workflows
- **devops-power** - Deployment and CI/CD workflows
- **database-power** - Database management and queries

Powers combine documentation, steering files, and MCP servers into shareable units.

---

## Configuration Examples

### TDD Workflow Hook

```json
{
  "name": "TDD Enforcer",
  "eventType": "fileEdited",
  "filePatterns": ["src/**/*.ts"],
  "hookAction": "askAgent",
  "outputPrompt": "Use the test-engineer agent to ensure this file has corresponding tests with 80%+ coverage. If tests don't exist, create them following TDD principles."
}
```

### Security Review Hook

```json
{
  "name": "Security Audit on Tool Use",
  "eventType": "preToolUse",
  "toolTypes": ["write"],
  "hookAction": "askAgent",
  "outputPrompt": "Before writing code that handles authentication or sensitive data, verify it follows security best practices."
}
```

### Spec Task Completion Hook

```json
{
  "name": "Run Tests After Task",
  "eventType": "postTaskExecution",
  "hookAction": "runCommand",
  "command": "npm test"
}
```

---

## Best Practices

### Context Management
- Keep steering rules focused and actionable
- Use specific file patterns in hooks to avoid noise
- Regularly review and update agent prompts
- Monitor context window usage (keep under 80%)

### Agent Delegation
- Use architect agent for high-level design decisions
- Delegate code reviews to code-reviewer agent before merging
- Let test-engineer agent handle all testing-related tasks
- Use debug-detective for complex bug investigations

### MCP Integration
- Start with essential services (database, git, cloud)
- Keep under 10 MCPs enabled per project
- Use environment variables for all sensitive configuration
- Disable unused MCPs to preserve context window

### Hook Automation
- Begin with simple file watchers for formatting and linting
- Add git hooks for commit message validation
- Implement deployment hooks only after thorough testing
- Use preToolUse hooks for access control and validation

### Spec-Driven Development
- Create specs for complex features (> 3 files affected)
- Break down into small, verifiable tasks
- Use file references to include relevant documentation
- Review and update specs as requirements evolve

---

## Comparison with Claude Code

This repository is inspired by [everything-claude-code](https://github.com/affaan-m/everything-claude-code) but adapted specifically for Kiro IDE.

**Key Differences:**
- Kiro-specific features (specs, hooks, steering)
- Kiro IDE workflow patterns
- Context management for Kiro
- MCP configuration for Kiro

**Shared Concepts:**
- Agent-based delegation
- Skills for domain knowledge
- Rules for always-follow guidelines
- MCP server integrations

---

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=iamaanahmad/everything-kiro-ide&type=date&legend=top-left)](https://www.star-history.com/#iamaanahmad/everything-kiro-ide&type=date&legend=top-left)

## Contributing

Contributions are welcome! If you have:
- New agent specializations
- Improved workflow patterns
- Additional MCP integrations
- Better hook configurations
- Spec templates

Please submit a pull request. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## Roadmap

### Phase 1: Core Foundation ✅
- Essential agent collection
- Basic MCP integrations
- Fundamental hooks and steering rules
- Spec templates

### Phase 2: Advanced Workflows 🚧
- Multi-agent collaboration patterns
- Complex deployment pipelines
- Advanced monitoring and alerting
- Spec-driven development workflows

### Phase 3: AI-Enhanced Development 🔮
- Predictive code suggestions
- Automated refactoring agents
- Intelligent test generation
- Performance optimization automation

---

## Resources

- **Kiro IDE:** [Official Website](https://kiro.dev)
- **MCP Protocol:** https://modelcontextprotocol.io
- **Inspired by:** [everything-claude-code](https://github.com/affaan-m/everything-claude-code)

---

## License

MIT - Use freely, modify as needed, contribute back if you can.

---

**Transform your development workflow with AI-powered automation. Start with everything-kiro and build something extraordinary.**

Star this repo if it helps. Customize for your needs. Build something great.
