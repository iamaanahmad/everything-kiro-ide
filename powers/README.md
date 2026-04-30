# Kiro Powers

**Powers package documentation, workflow guides (steering files), and optionally MCP servers into reusable, shareable units.**

Powers are Kiro's way of packaging capabilities for easy distribution and reuse. Think of them as plugins that can include documentation, steering files, and MCP server integrations.

---

## What are Powers?

Powers provide:
- **Minimal context**: See 5 actions for all powers instead of dozens of tools per power
- **Structured discovery**: Use "activate" to discover capabilities on-demand
- **Full functionality**: Complete tool schemas and documentation
- **Guided workflows**: POWER.md files and steering guides for optimal usage

---

## Power Structure

```
my-power/
├── POWER.md              # Main documentation (required)
├── steering/             # Workflow guides (optional)
│   ├── getting-started.md
│   ├── advanced-usage.md
│   └── troubleshooting.md
├── mcp-servers/          # MCP server configs (optional)
│   └── server-config.json
└── power.json            # Power metadata (required)
```

---

## Power Actions

### 1. LIST - See all installed powers
```
User: List my powers

Kiro: [Shows all installed powers with descriptions and keywords]
```

### 2. ACTIVATE - Load power documentation and tools
```
User: Activate the database power

Kiro: [Loads POWER.md, steering files, and MCP tools]
```

**CRITICAL:** Always activate a power before using it to understand:
- Available tools and their parameters
- Workflow guides and best practices
- Proper usage patterns

### 3. USE - Execute power tools
```
User: Use database power to query users table

Kiro: [Executes tool from activated power]
```

### 4. READ_STEERING - Get detailed workflow guides
```
User: Read the getting-started guide from database power

Kiro: [Shows detailed workflow instructions]
```

### 5. CONFIGURE - Open powers management panel
```
User: Configure powers

Kiro: [Opens Powers side panel for browsing and installation]
```

---

## Creating a Power

### Step 1: Create Power Structure

```bash
mkdir my-awesome-power
cd my-awesome-power
```

### Step 2: Create power.json

```json
{
  "name": "my-awesome-power",
  "displayName": "My Awesome Power",
  "version": "1.0.0",
  "description": "Does awesome things for your project",
  "keywords": ["awesome", "productivity", "automation"],
  "author": "Your Name",
  "mcpServers": {
    "awesome-server": {
      "command": "uvx",
      "args": ["mcp-server-awesome"],
      "env": {
        "API_KEY": "your_key_here"
      }
    }
  }
}
```

### Step 3: Create POWER.md

```markdown
# My Awesome Power

**One-line description of what this power does.**

## Overview

Detailed explanation of the power's capabilities and use cases.

## Features

- Feature 1: Description
- Feature 2: Description
- Feature 3: Description

## Quick Start

1. Activate the power: `activate my-awesome-power`
2. Use a tool: `use my-awesome-power to do something`
3. Read guides: `read steering file getting-started.md`

## Available Tools

### Tool 1: do_something
**Description:** Does something awesome

**Parameters:**
- `input` (string, required): The input to process
- `options` (object, optional): Additional options

**Example:**
\`\`\`
use my-awesome-power do_something with input="test"
\`\`\`

### Tool 2: do_another_thing
**Description:** Does another awesome thing

**Parameters:**
- `target` (string, required): The target to process

## Best Practices

1. Always activate before using
2. Read steering guides for complex workflows
3. Check tool parameters before execution

## Troubleshooting

### Issue 1
**Problem:** Tool fails with error X
**Solution:** Check that API_KEY is configured

### Issue 2
**Problem:** Power not found
**Solution:** Ensure power is installed via configure panel

## Examples

### Example 1: Basic Usage
\`\`\`
activate my-awesome-power
use my-awesome-power do_something with input="hello"
\`\`\`

### Example 2: Advanced Usage
\`\`\`
activate my-awesome-power
read steering advanced-usage.md
use my-awesome-power do_another_thing with target="advanced"
\`\`\`
```

### Step 4: Create Steering Files (Optional)

```markdown
# steering/getting-started.md

# Getting Started with My Awesome Power

## Prerequisites

- Requirement 1
- Requirement 2

## Step-by-Step Guide

### 1. Initial Setup
[Detailed instructions]

### 2. First Use
[Detailed instructions]

### 3. Verification
[How to verify it's working]

## Next Steps

- Read advanced-usage.md for more features
- Check troubleshooting.md if you encounter issues
```

---

## Example Powers

### Database Power

```json
{
  "name": "database-power",
  "displayName": "Database Management Power",
  "version": "1.0.0",
  "description": "Manage PostgreSQL, MySQL, and MongoDB databases",
  "keywords": ["database", "sql", "postgres", "mysql", "mongodb"],
  "mcpServers": {
    "postgres": {
      "command": "uvx",
      "args": ["mcp-server-postgres"],
      "env": {
        "POSTGRES_CONNECTION_STRING": "postgresql://user:pass@localhost:5432/db"
      }
    },
    "mongodb": {
      "command": "uvx",
      "args": ["mcp-server-mongodb"],
      "env": {
        "MONGODB_URI": "mongodb://localhost:27017"
      }
    }
  }
}
```

### GitHub Power

```json
{
  "name": "github-power",
  "displayName": "GitHub Integration Power",
  "version": "1.0.0",
  "description": "Manage GitHub repositories, PRs, and issues",
  "keywords": ["github", "git", "pr", "issues", "repository"],
  "mcpServers": {
    "github": {
      "command": "uvx",
      "args": ["mcp-server-github"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_your_token_here"
      }
    }
  }
}
```

### Testing Power

```json
{
  "name": "testing-power",
  "displayName": "Testing & QA Power",
  "version": "1.0.0",
  "description": "Comprehensive testing tools and workflows",
  "keywords": ["testing", "qa", "tdd", "e2e", "unit-tests"],
  "mcpServers": {}
}
```

**Note:** This power uses only documentation and steering files, no MCP servers.

---

## Power Workflow Examples

### Workflow 1: Database Query

```
User: I need to query the users table

Kiro: Let me activate the database power first.
[Activates database-power]

Kiro: The database power provides these tools:
- query_postgres: Execute PostgreSQL queries
- query_mongodb: Execute MongoDB queries
- list_tables: List all tables
- describe_table: Get table schema

User: Query all active users

Kiro: [Uses query_postgres tool]
SELECT * FROM users WHERE is_active = true;

Results: [Shows query results]
```

### Workflow 2: GitHub PR Management

```
User: Create a PR for my feature branch

Kiro: Activating GitHub power...
[Activates github-power]

Kiro: I'll create a pull request. Let me check the current branch and changes.
[Uses github tools to create PR]

PR created: #123 - "Add user authentication"
```

### Workflow 3: TDD Workflow

```
User: Help me implement TDD for user service

Kiro: Activating testing power...
[Activates testing-power]

Kiro: Let me read the TDD workflow guide.
[Reads steering/tdd-workflow.md]

Kiro: Following TDD methodology:

Step 1 (RED): Write failing test
[Creates test file]

Step 2 (GREEN): Implement minimal code
[Creates implementation]

Step 3 (REFACTOR): Improve code
[Refactors while keeping tests green]
```

---

## Power Best Practices

### DO
- ✅ Always activate power before using
- ✅ Read steering guides for complex workflows
- ✅ Use descriptive keywords for discoverability
- ✅ Document all tools with examples
- ✅ Provide troubleshooting guides
- ✅ Keep POWER.md concise and clear
- ✅ Version your powers properly

### DON'T
- ❌ Use power without activating first
- ❌ Guess tool names or parameters
- ❌ Skip documentation
- ❌ Hardcode secrets in power.json
- ❌ Create powers with too many responsibilities
- ❌ Forget to update version on changes

---

## Power Discovery

### Keyword Matching

**CRITICAL:** When you see words in the user's message that match a power's keywords, **immediately and proactively activate that power**.

**Examples:**
- User mentions "database" or "sql" → Activate database-power
- User asks about "github" or "pr" → Activate github-power
- User talks about "testing" or "tdd" → Activate testing-power

Keywords are your strongest signal to activate a power!

---

## Installing Powers

### Method 1: From Marketplace

```
User: Configure powers

Kiro: [Opens Powers panel]
[User browses and installs from marketplace]
```

### Method 2: From Local Directory

```bash
# Copy power to Kiro powers directory
cp -r my-awesome-power ~/.kiro/powers/

# Or workspace-specific
cp -r my-awesome-power .kiro/powers/
```

### Method 3: From Git Repository

```bash
git clone https://github.com/user/awesome-power.git ~/.kiro/powers/awesome-power
```

---

## Power Management

### List Installed Powers

```
User: List my powers

Kiro: Installed Powers:
1. database-power - Database management (postgres, mysql, mongodb)
2. github-power - GitHub integration (pr, issues, repos)
3. testing-power - Testing workflows (tdd, e2e, unit-tests)
```

### Activate a Power

```
User: Activate database power

Kiro: Activating database-power...

Overview: Manage PostgreSQL, MySQL, and MongoDB databases

Available Tools:
- query_postgres: Execute PostgreSQL queries
- query_mongodb: Execute MongoDB queries
- list_tables: List all tables
- describe_table: Get table schema

Steering Files:
- getting-started.md
- advanced-queries.md
- troubleshooting.md
```

### Use a Power Tool

```
User: Use database power to list tables

Kiro: [Executes list_tables tool]

Tables in database:
- users
- posts
- comments
- sessions
```

---

## Creating Shareable Powers

### 1. Package Your Power

```bash
# Create distributable package
tar -czf my-awesome-power-v1.0.0.tar.gz my-awesome-power/
```

### 2. Publish to GitHub

```bash
git init
git add .
git commit -m "Initial release of my-awesome-power"
git remote add origin https://github.com/user/my-awesome-power.git
git push -u origin main
```

### 3. Create Release

```markdown
# Release Notes v1.0.0

## Features
- Feature 1
- Feature 2

## Installation
\`\`\`bash
git clone https://github.com/user/my-awesome-power.git ~/.kiro/powers/my-awesome-power
\`\`\`

## Usage
\`\`\`
activate my-awesome-power
use my-awesome-power do_something
\`\`\`
```

---

## Power Examples in This Repository

### 1. Development Power
**Location:** `powers/development-power/`
**Features:** Code review, testing, debugging workflows
**Keywords:** development, code, review, testing

### 2. DevOps Power
**Location:** `powers/devops-power/`
**Features:** Deployment, CI/CD, monitoring
**Keywords:** devops, deployment, cicd, docker, kubernetes

### 3. Database Power
**Location:** `powers/database-power/`
**Features:** Database management and queries
**Keywords:** database, sql, postgres, mongodb

---

## Troubleshooting

### Power Not Found

**Problem:** "Power 'my-power' not found"

**Solutions:**
1. Check power is installed: List powers
2. Verify power name matches power.json
3. Ensure power directory is in ~/.kiro/powers/ or .kiro/powers/

### Tool Not Available

**Problem:** "Tool 'my_tool' not available"

**Solutions:**
1. Activate power first: `activate my-power`
2. Check tool name in POWER.md documentation
3. Verify MCP server is configured correctly

### MCP Server Connection Failed

**Problem:** "Failed to connect to MCP server"

**Solutions:**
1. Check API keys are configured in power.json
2. Verify MCP server package is installed
3. Check network connectivity
4. Review MCP server logs

---

## Resources

- **Kiro Powers Documentation:** [Official Docs](https://docs.kiro.dev/powers)
- **MCP Protocol:** https://modelcontextprotocol.io
- **Example Powers:** See `powers/` directory in this repository

---

## Contributing Powers

Want to contribute a power to this repository?

1. Create your power following the structure above
2. Test thoroughly in a real project
3. Document all features and tools
4. Submit a pull request

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

---

**Powers make Kiro extensible and shareable. Create powers for your workflows and share them with the community!**
