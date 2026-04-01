---
name: skill-writer
description: Interactive workflow to create, write, and validate Agent Skills for Claude Code. Use when the user wants to create a new skill, author or revise SKILL.md, design frontmatter, fix skill discovery or triggering issues, or convert an existing prompt or workflow into a portable skill folder.
---

# Skill Writer

You guide the user through building a correct, discoverable, and testable Agent Skill folder. Your job is to produce a working skill, not a vague explanation.

## Compatibility

Works in Claude Code and Claude.ai. Assumes access to local files and a standard skill folder structure.

## Outcomes

By the end, the user has:
1. A correctly named skill folder in the right location
2. A valid SKILL.md with YAML frontmatter that triggers reliably
3. Clear step by step instructions and examples
4. A lightweight testing plan for triggering, functional behavior, and iteration

## Core principles

Progressive disclosure (staged loading): Keep frontmatter compact, keep SKILL.md focused, move deep detail into references when needed.
Composability (works alongside others): Do not assume you are the only enabled skill.
Portability (same folder works across surfaces): Avoid environment specific assumptions unless stated in compatibility.

## Instructions

### Step 1: Define scope and success

Ask only what is necessary, then proceed.

Collect:
1. Capability: what exact workflow does the skill perform
2. Triggers: user phrases that should activate it
3. Inputs: files, links, or parameters the user will provide
4. Outputs: what the user should receive at the end
5. Constraints: tools allowed, read only vs write, team sharing vs personal

Define success criteria:
- Triggers on most relevant queries
- Does not trigger on unrelated queries
- Produces consistent structure across runs

Use precise language, but keep scope narrow. One skill equals one capability.

Vocabulary standard:
- specificity (Konkretheit): user can test it in one prompt
- validation (Pruefung): deterministic checks before claiming done
- coherence (Stimmigkeit): instructions do not contradict themselves

### Step 2: Choose location

Decide based on usage:

Personal skills:
- Path: ~/.claude/skills/skill-name
- Use for personal workflows, experiments, private preferences

Project skills:
- Path: .claude/skills/skill-name
- Use for team conventions, shared utilities, versioned in git

If the user is building for a team, default to project skills.

### Step 3: Create folder structure

Default minimal structure:
skill-name/
  SKILL.md

Optional additions only if justified:
- scripts/ for executable helpers
- references/ for deep docs and advanced options
- assets/ for templates, icons, formatting artifacts

Never add README.md inside the skill folder.

### Step 4: Generate frontmatter that triggers reliably

Create YAML frontmatter first. It is the most important component for discovery.

Required fields:
- name: kebab case only, matches folder name exactly
- description: what it does and when to use it, include trigger phrases

Rules:
- No angle brackets anywhere in frontmatter
- Keep description under 1024 characters
- No reserved names in name field

Produce a draft, then immediately sanity check it:
- Would a user naturally say these trigger phrases
- Does it risk overtriggering on generic words
- Does it mention concrete actions and relevant file types if applicable

### Step 5: Write SKILL.md body as an executable workflow

Write instructions for Claude, not for humans.

Required sections in this order:

1. What the skill does
2. Quick start
3. Workflow steps with validation gates
4. Examples: at least two, with realistic user phrasing
5. Testing plan: triggering tests and functional tests
6. Troubleshooting: common errors and fixes

Enforce validation gates (quality gates):
- Name rules verified
- SKILL.md exists and spelled correctly
- Frontmatter delimiters present
- No disallowed characters in frontmatter
- Description includes both what and when

### Step 6: Convert prompts or workflows into skill steps

If the user provides a long prompt, do this:
1. Extract intent, inputs, outputs
2. Turn it into numbered steps
3. Add decision points where ambiguity exists
4. Add explicit stop conditions
5. Add error handling for predictable failures

Use the following patterns when appropriate:
- Sequential orchestration: strict step ordering
- Iterative refinement: draft, check, refine loop
- Context aware selection: choose method based on file type or constraints
- Domain intelligence: embed best practices and checklists

### Step 7: Provide a compact test suite

Triggering tests:
- 10 to 20 prompts that should trigger
- 10 prompts that should not trigger

Functional tests:
- One simple success case
- One edge case
- One failure mode with expected handling

Performance comparison (optional):
- Compare messages and tool calls with and without the skill

### Step 8: Debugging playbook

If the skill does not upload:
- Verify SKILL.md exact spelling and casing
- Verify frontmatter delimiters and valid YAML
- Verify folder naming in kebab case

If it does not trigger:
- Make description more concrete
- Add trigger phrases users actually say
- Add file extensions if relevant
- Reduce generic keywords

If it triggers too often:
- Narrow scope
- Add explicit negative triggers in description
- Remove broad words like help, analyze, process unless paired with specifics

## Quick start template you generate for users

When creating a new skill, produce a complete SKILL.md draft with:
- frontmatter
- step workflow
- examples
- tests
- troubleshooting

Then provide install instructions:
- create folder in correct location
- restart Claude Code
- run 3 trigger prompts to verify behavior

## Output contract

When the user asks you to create or improve a skill, you must output:

1. Suggested skill name in kebab case
2. Suggested location: personal or project
3. Final SKILL.md content ready to paste
4. Optional supporting files list if needed
5. Triggering test prompts and non trigger prompts

Do not stop at advice. Produce the artifact.

## Examples you can follow

Example user requests that should activate this skill:
- Create a new skill for generating investor one pagers
- Write SKILL.md for a PDF extraction workflow
- My skill will not trigger, fix the description
- Convert this long prompt into a reusable skill
- Design frontmatter and structure for a Claude Code skill

Non trigger examples:
- General coding questions not about skills
- Writing a normal document without skill creation intent
- Debugging an app unrelated to skills

## Related skills

- **owasp-security**: If the skill handles secrets or security
- **test-driven-development**: If the skill produces code that needs tests
- **varlock**: If the skill handles environment variables or credentials
