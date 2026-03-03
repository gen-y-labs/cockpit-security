# Cockpit Security

Cockpit Security is a Cockpit plugin that provides host security visibility across three tabs:

- `Updates`: pending security updates from native package manager providers
- `Vulnerabilities`: on-demand vulnerability scan results (Trivy)
- `Compliance`: OpenSCAP compliance results

It follows Cockpit UI conventions and keeps scan execution logic separate from UI components.

## Runtime Requirements

- Cockpit server/runtime
- For `Updates` tab:
  - openSUSE: `zypper`
  - Ubuntu/Debian: `apt`
- For `Vulnerabilities` tab:
  - `trivy` installed on host
- For `Compliance` tab:
  - openSUSE: `openscap-utils`, `scap-security-guide`
  - Ubuntu/Debian: `openscap-scanner`, `ssg-base`

## Install (openSUSE)

```bash
sudo zypper install -y cockpit cockpit-bridge nodejs npm make gettext-runtime
sudo zypper install -y openscap-utils scap-security-guide
# optional for Vulnerabilities tab
sudo zypper install -y trivy
```

Build and install plugin:

```bash
git clone https://github.com/cockpit-project/security.git
cd security
make
sudo make install
```

## Install (Ubuntu)

```bash
sudo apt update
sudo apt install -y cockpit nodejs npm make gettext
sudo apt install -y openscap-scanner ssg-base
# optional for Vulnerabilities tab
# install trivy from your preferred repository
```

Build and install plugin:

```bash
git clone https://github.com/cockpit-project/security.git
cd security
make
sudo make install
```

## Development

Use a development symlink:

```bash
make devel-install
```

Watch mode:

```bash
make watch
```

Code quality checks:

```bash
npm run eslint
npm run stylelint
```

## Screenshots

### Updates Tab

![Updates tab](docs/screenshots/updates-tab.png)

### Vulnerabilities Tab

![Vulnerabilities tab](docs/screenshots/vulnerabilities-tab.png)

### Compliance Tab

![Compliance tab](docs/screenshots/compliance-tab.png)

## Additional Documents

- [SECURITY_MODEL.md](SECURITY_MODEL.md)
- [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
