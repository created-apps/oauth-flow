# Stand-in Static UI

This is a minimal, temporary static HTML/CSS/JS frontend for managing OAuth connections.
It talks directly to the same backend REST API endpoints (`/users`, `/auth/connections`, `/auth/:provider/authorize`, `/auth/:provider/disconnect`) that a production application will consume.
To upgrade to a React/Next.js frontend in the future, simply place your compiled static build assets in this `public/` directory with zero backend changes required.
