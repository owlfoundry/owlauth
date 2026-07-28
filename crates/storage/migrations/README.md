# Embedded database migrations

Versioned database migrations for OwlAuth storage belong in this directory. The storage crate must embed them into the server binary and apply pending migrations automatically during startup before serving requests.

Automatic migration must be transactional where the database supports it, safe to retry, and fail startup without partially exposing a newer server against an older schema. Destructive or irreversible migrations require an explicit compatibility and recovery plan.
