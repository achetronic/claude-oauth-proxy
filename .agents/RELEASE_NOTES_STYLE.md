# Release Notes Style Guide

## Format

```markdown
## vX.Y.Z

One sentence summarizing the release (optional for patch releases).

### Features
- New capabilities added in this release

### Improvements
- Enhancements to existing functionality

### Bug Fixes
- Issues resolved in this release

### Breaking Changes
- Anything that requires user action to migrate (omit section if none)

### Notes
- Important caveats, requirements, or context the user should know
```

## Rules

- Use past tense for bug fixes ("Fixed X"), present for features ("Adds X") and improvements ("Improves X")
- One item per line, no sub-bullets
- Omit empty sections entirely
- Keep each item to a single line — no paragraphs
- No emojis
- No "we" or "I" — passive or direct voice only
- `Notes` is for things the user must know (requirements, compatibility, caveats)
- Breaking changes always get their own section and must describe the migration path
