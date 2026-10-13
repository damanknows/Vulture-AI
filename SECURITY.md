# Security Policy

## Responsible Disclosure

The Vulture-AI project takes software security seriously. Because this project contains network scanning orchestration and vulnerability management logic, safe operation is paramount.

### Reporting Security Vulnerabilities

If you identify a security vulnerability in Vulture-AI (e.g., an unauthorized scanning bypass, injection filter flaw, or input validation bug):

1. **Do not** file a public GitHub issue.
2. Please report the issue privately through **GitHub Private Vulnerability Reporting** via the repository Security tab at:
   https://github.com/damanknows/Vulture-AI/security/advisories/new
3. Alternatively, contact the repository maintainer directly through their verified GitHub profile:
   https://github.com/damanknows

*Note: A dedicated security contact email address has not yet been configured in the repository settings. Please utilize GitHub Security Advisories for encrypted, private reporting.*

### Supported Versions

| Version | Supported |
|:---|:---:|
| 0.2.x (`research-v2`) | :white_check_mark: |
| < 0.2.0 | :x: |

### Operational Security Warnings

- **Authorized Scanning Only**: Network scanning using `scanner.py` must only be executed against IP addresses and subnets explicitly authorized by asset owners.
- **Server Allowlist**: Always configure `VULTURE_ALLOWED_TARGETS` in your environment. By default, unlisted targets are rejected.
- **Offline Tests**: All automated unit tests in `tests/` execute against offline mocks or local test fixtures.
