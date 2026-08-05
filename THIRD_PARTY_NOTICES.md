# Third-party notices

sshscope directly depends on:

- `github.com/spf13/cobra`
- `github.com/spf13/pflag`
- `github.com/inconshreveable/mousetrap`
- `golang.org/x/crypto`
- `golang.org/x/sys`
- `golang.org/x/time`
- `gopkg.in/yaml.v3`

The optional web UI additionally uses the frontend packages pinned in
`cmd/sshscope-web/frontend/pnpm-lock.yaml`, including React, Vite, Tailwind CSS,
and Lucide React.

Run `make release` to collect Go dependency license texts into
`dist/THIRD_PARTY_LICENSES.txt`. A production web distributable should also
bundle the complete license texts for the pinned frontend dependency graph.
