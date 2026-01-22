# Everything Kiro

**The complete collection of Kiro configs, agents, skills, hooks, and MCP integrations for maximum productivity.**

Production-ready configurations evolved from analyzing the best practices of Claude Code and adapted specifically for Kiro's unique capabilities and architecture.

---

## The Philosophy

Kiro is more than just an IDE - it's an AI-powered development environment that can understand context, execute commands, manage files, and integrate with external services through MCP (Model Context Protocol). This collection provides battle-tested configurations to unlock Kiro's full potential.

### What Makes This Different

Unlike traditional IDE configurations, everything-kiro leverages:
- **AI-First Workflow**: Agents that understand your codebase and make intelligent decisions
- **Context-Aware Automation**: Hooks that trigger based on file changes, git events, and development lifecycle
- **MCP Integration**: Seamless connection to databases, APIs, cloud services, and development tools
- **Intelligent Delegation**: Sub-agents for specialized tasks like code review, testing, and deployment
- **Memory Persistence**: Context that survives across sessions for continuous learning

---

## What's Inside

```
everything-kiro/
|-- .kiro/                    # Kiro-specific configurations
|   |-- settings/
|   |   |-- mcp.json         # MCP server configurations
|   |   |-- hooks.json       # Event-driven automations
|   |-- steering/            # Always-active context and guidelines
|   |   |-- coding-standards.md
|   |   |-- security-rules.md
|   |   |-- project-patterns.md
|
|-- agents/                  # Specialized sub-agents
|   |-- architect.md         # System design and planning
|   |-- code-reviewer.md     # Quality and security review
|   |-- test-engineer.md     # TDD and testing workflows
|   |-- devops-specialist.md # Deployment and infrastructure
|   |-- debug-detective.md   # Bug investigation and fixing
|   |-- performance-optimizer.md
|   |-- security-auditor.md
|   |-- documentation-writer.md
|
|-- skills/                  # Reusable workflow patterns
|   |-- development-workflows/
|   |   |-- tdd-cycle.md
|   |   |-- git-flow.md
|   |   |-- code-review-process.md
|   |-- language-patterns/
|   |   |-- typescript-best-practices.md
|   |   |-- python-conventions.md
|   |   |-- react-patterns.md
|   |-- infrastructure/
|   |   |-- docker-workflows.md
|   |   |-- ci-cd-patterns.md
|   |   |-- monitoring-setup.md
|
|-- hooks/                   # Event-driven automations
|   |-- file-watchers/       # React to file changes
|   |-- git-integrations/    # Git workflow automation
|   |-- build-monitors/      # Build and test automation
|   |-- deployment-triggers/ # Deployment workflows
|
|-- mcp-configs/            # MCP server configurations
|   |-- databases/          # Database connections
|   |-- cloud-services/     # AWS, GCP, Azure integrations
|   |-- development-tools/  # GitHub, Jira, Slack, etc.
|   |-- monitoring/         # Logging and metrics
|
|-- examples/               # Example projects and configurations
|   |-- fullstack-webapp/   # Complete web application setup
|   |-- microservices/      # Microservices architecture
|   |-- data-pipeline/      # Data engineering project
|
|-- templates/              # Project scaffolding templates
|   |-- react-typescript/
|   |-- node-api/
|   |-- python-fastapi/
|   |-- go-microservice/
```

---

## Quick Start

### 1. Install as Kiro Extension

```bash
# Clone this repository
git clone https://github.com/your-username/everything-kiro.git

# Copy to your Kiro workspace
cp -r everything-kiro/.kiro/* .kiro/
```

### 2. Configure MCP Servers

Edit `.kiro/settings/mcp.json` and add your API keys:

```json
{
  "mcpServers": {
    "github": {
      "command": "uvx",
      "args": ["mcp-server-github"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "your_token_here"
      }
    },
    "postgres": {
      "command": "uvx", 
      "args": ["mcp-server-postgres"],
      "env": {
        "POSTGRES_CONNECTION_STRING": "your_connection_string"
      }
    }
  }
}
```

### 3. Enable Steering Rules

Steering rules are automatically loaded from `.kiro/steering/` and provide always-active context to guide Kiro's behavior.

### 4. Start Using Agents

Delegate specialized tasks to sub-agents:

```
"Use the architect agent to design a microservices architecture for this e-commerce platform"

"Have the code-reviewer agent analyze this pull request for security issues"

"Ask the test-engineer agent to implement comprehensive tests for the user authentication module"
```

---

## Key Features

### 🤖 Intelligent Agents

**Architect Agent**: Designs system architecture, creates implementation plans, identifies technical debt.

**Code Reviewer**: Performs security audits, checks coding standards, suggests improvements.

**Test Engineer**: Implements TDD workflows, ensures test coverage, creates E2E tests.

**DevOps Specialist**: Manages deployments, configures CI/CD, monitors infrastructure.

**Debug Detective**: Investigates bugs, analyzes logs, suggests fixes.

### ⚡ Smart Hooks

**File Watchers**: Auto-format code, run tests, update documentation when files change.

**Git Integration**: Automated PR creation, commit message validation, branch protection.

**Build Monitors**: Continuous testing, deployment triggers, performance monitoring.

### 🔌 MCP Integrations

**Databases**: Direct connection to PostgreSQL, MySQL, MongoDB, Redis.

**Cloud Services**: AWS, GCP, Azure resource management and monitoring.

**Development Tools**: GitHub, GitLab, Jira, Slack, Discord integrations.

**Monitoring**: Datadog, New Relic, Prometheus metrics and alerting.

### 📚 Reusable Skills

**Development Workflows**: TDD cycles, code review processes, git workflows.

**Language Patterns**: Best practices for TypeScript, Python, Go, Rust.

**Infrastructure**: Docker containerization, Kubernetes deployment, monitoring setup.

---

## Configuration Examples

### TDD Workflow Hook

```json
{
  "name": "TDD Enforcer",
  "eventType": "fileEdited",
  "filePatterns": ["src/**/*.ts", "src/**/*.js"],
  "hookAction": "askAgent",
  "outputPrompt": "Use the test-engineer agent to ensure this file has corresponding tests with 80%+ coverage. If tests don't exist, create them following TDD principles."
}
```

### Security Review Hook

```json
{
  "name": "Security Audit",
  "eventType": "promptSubmit",
  "hookAction": "askAgent", 
  "outputPrompt": "Before implementing any authentication or data handling code, consult the security-auditor agent to review the approach for vulnerabilities."
}
```

### Auto-Deploy Hook

```json
{
  "name": "Auto Deploy",
  "eventType": "agentStop",
  "hookAction": "runCommand",
  "command": "if git diff --quiet HEAD~1 HEAD -- package.json; then echo 'No deployment needed'; else npm run deploy:staging; fi"
}
```

---

## Agent Specializations

### 🏗️ Architect Agent
- System design and architecture decisions
- Technology stack recommendations  
- Performance and scalability planning
- Technical debt identification
- Migration strategies

### 🔍 Code Reviewer Agent
- Security vulnerability scanning
- Code quality assessment
- Performance optimization suggestions
- Best practices enforcement
- Documentation completeness

### 🧪 Test Engineer Agent
- TDD workflow implementation
- Test coverage analysis
- E2E test creation
- Performance testing
- Test automation setup

### 🚀 DevOps Specialist Agent
- CI/CD pipeline configuration
- Infrastructure as Code
- Deployment automation
- Monitoring and alerting setup
- Container orchestration

### 🐛 Debug Detective Agent
- Bug reproduction and analysis
- Log analysis and correlation
- Performance profiling
- Root cause analysis
- Fix verification

---

## MCP Server Ecosystem

### Database Connections
- **PostgreSQL**: Query execution, schema management, performance monitoring
- **MongoDB**: Document operations, aggregation pipelines, index optimization
- **Redis**: Cache management, session storage, pub/sub messaging

### Cloud Services
- **AWS**: EC2, S3, Lambda, RDS, CloudWatch integration
- **GCP**: Compute Engine, Cloud Storage, BigQuery, Cloud Functions
- **Azure**: Virtual Machines, Blob Storage, SQL Database, Functions

### Development Tools
- **GitHub**: Repository management, PR automation, issue tracking
- **Jira**: Project management, sprint planning, issue resolution
- **Slack**: Team communication, deployment notifications, alerts

### Monitoring & Observability
- **Datadog**: Application performance monitoring, log aggregation
- **New Relic**: Performance insights, error tracking, alerting
- **Prometheus**: Metrics collection, alerting rules, dashboard creation

---

## Best Practices

### Context Management
- Keep steering rules focused and actionable
- Use specific file patterns in hooks to avoid noise
- Regularly review and update agent prompts based on project evolution

### Agent Delegation
- Use the architect agent for high-level design decisions
- Delegate code reviews to the code-reviewer agent before merging
- Let the test-engineer agent handle all testing-related tasks

### MCP Integration
- Start with essential services (database, git, cloud)
- Add monitoring and alerting early in the project lifecycle
- Use environment variables for all sensitive configuration

### Hook Automation
- Begin with simple file watchers for formatting and linting
- Add git hooks for commit message validation and PR automation
- Implement deployment hooks only after thorough testing

---

## Contributing

This collection thrives on community contributions. Whether you have:
- New agent specializations
- Improved workflow patterns
- Additional MCP integrations
- Better hook configurations

Your contributions make this resource better for everyone.

### Contribution Guidelines
1. Test all configurations in a real project environment
2. Document the use case and benefits clearly
3. Follow the established naming and structure conventions
4. Include example usage and expected outcomes

---

## Roadmap

### Phase 1: Core Foundation ✅
- Basic agent collection
- Essential MCP integrations
- Fundamental hooks and steering rules

### Phase 2: Advanced Workflows 🚧
- Multi-agent collaboration patterns
- Complex deployment pipelines
- Advanced monitoring and alerting

### Phase 3: AI-Enhanced Development 🔮
- Predictive code suggestions
- Automated refactoring agents
- Intelligent test generation
- Performance optimization automation

---

## License

MIT - Use freely, modify as needed, contribute back when you can.

---

**Transform your development workflow with AI-powered automation. Start with everything-kiro and build something extraordinary.**
