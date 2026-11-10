# Security policy

TaintTrap is a security tool, so a way around it is a vulnerability in its own right. Thank you for taking the time to report one privately.

## Supported versions

Until 1.0, only the latest release receives security fixes.

| Version | Supported |
| --- | --- |
| latest 0.x | yes |
| older | no |

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: <https://github.com/Alexli18/tainttrap/security/advisories/new>.

Do not open a public issue, pull request or discussion for anything below.

Please include:

- TaintTrap version, integration (Claude Code hook or MCP proxy), mode, and the relevant part of your policy;
- the user's task, the tool call or calls, and the tool output that led to them, with real secrets and private data replaced;
- what TaintTrap decided and what it should have decided;
- whether the attack needs anything beyond controlling content the agent reads (for example, local shell access, a malicious package, or changing TaintTrap's own files).

## What counts as a vulnerability

- A tool call that a documented guarantee says is blocked or asked goes through in soft or strict mode.
- A way for the agent, or any process it starts, to approve a request, remember a recipient, reload or loosen the policy, or disable TaintTrap without the human proof TaintTrap requires.
- A secret TaintTrap has seen appearing in its logs, socket replies, reports, judge prompts or the reasons it returns to the agent.
- An error, timeout or malformed input that makes TaintTrap allow a call it would otherwise ask about or block.
- A network connection that TaintTrap opens on its own when the LLM judge is turned off. Traffic the MCP proxy forwards to MCP servers you configured does not count.

## What does not

- Attacks listed as not covered in [docs/threat-model.md](docs/threat-model.md). New examples of them are welcome through the public "Known limitation" issue form.
- Behaviour in observe mode, which by design never blocks.
- Attacks that need an attacker to already control your user account outside the agent, or root.
- A denial of service that fails closed (TaintTrap asks or blocks too much). Please report that as a public bug.

## What to expect

TaintTrap is maintained by one person, so these are targets, not guarantees:

- Acknowledgement within about 5 working days.
- An initial assessment within about 14 days.
- A fix or mitigation for a confirmed issue in a supported version before any public disclosure, coordinated with you.
- Credit in the advisory, unless you prefer otherwise.

If a report is declined, we will say why: not reproducible, out of scope, already known, or needing a stronger attack path.

## Official distribution

TaintTrap is distributed only through:

- the GitHub repository <https://github.com/Alexli18/tainttrap>;
- the PyPI package `tainttrap`, once it is published from this repository's release workflow with PyPI attestations. It is not on PyPI yet: until it is, install from the repository.

Copies from anywhere else are not maintained or reviewed by this project. The GitHub organization `TaintTrap` is an unrelated, older project.
