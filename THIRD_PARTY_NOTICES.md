# Third-Party Notices

This project depends on third-party software components.

## JavaScript/TypeScript Dependencies

Direct dependencies used by this project (from `package.json`) include:

- `@patternfly/patternfly` (MIT)
- `@patternfly/react-core` (MIT)
- `@patternfly/react-icons` (MIT)
- `@patternfly/react-styles` (MIT)
- `react` (MIT)
- `react-dom` (MIT)
- `esbuild` (MIT)
- `esbuild-sass-plugin` (MIT)
- `gettext-parser` (MIT)
- `argparse` (Python-2.0)

Development-time dependencies include TypeScript, ESLint, Stylelint, QUnit, and related plugins/configs (MIT/ISC/Apache-2.0 as declared in dependency metadata).

## Scanner and Host Tool Dependencies

Runtime features may use system tools provided by the host OS:

- Trivy (Aqua Security)
- OpenSCAP (`oscap`)
- SCAP Security Guide content
- Host package manager tools (`apt`, `zypper`)

These tools are distributed separately and are governed by their own licenses.

## License References

- Project license: `LICENSE` (LGPL-2.1-or-later)
- Dependency licenses: see each package's `LICENSE` file in `node_modules/` or upstream repository
- Distribution package licenses: see your distro package metadata
