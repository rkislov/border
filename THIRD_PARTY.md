# Third-party dependencies

Border's original source is Apache-2.0. Dependencies are separate works with their
own license terms. Exact versions and transitive dependencies are recorded in
`go.mod` and `go.sum`; their source and license files are available through the Go
module proxy and upstream repositories.

Direct dependencies:

- `filippo.io/age` — BSD-3-Clause; streaming encryption of recovery archives.

- `github.com/go-ldap/ldap/v3` — MIT; AD/FreeIPA LDAP client.
- `github.com/pquerna/otp` — Apache-2.0; TOTP enrollment and codes.

- `layeh.com/radius` — MPL-2.0; RADIUS packet codec and attribute helpers.
- `github.com/google/uuid` — BSD-3-Clause; audit identifiers.
- `github.com/jackc/pgx/v5` — MIT; PostgreSQL driver.
- `github.com/pressly/goose/v3` — MIT; database migrations.
- `github.com/spf13/cobra` — Apache-2.0; CLI.
- `golang.org/x/crypto` — BSD-3-Clause; password hashing.
- `golang.org/x/term` — BSD-3-Clause; interactive password input.
- `modernc.org/sqlite` — BSD-3-Clause; pure Go SQLite driver, incorporating SQLite
  (public domain) and additional separately licensed transitive components.

No third-party source files are modified or vendored in this repository. When
distributing compiled binaries, include the dependency license notices generated
for the exact build, and honor applicable source-availability obligations for
MPL-covered files. The original RADIUS library source is available at
https://github.com/layeh/radius.
