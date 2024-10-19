-- migrate:up transaction:false
CREATE TABLE sessions (
    token TEXT PRIMARY KEY,
    data BYTEA NOT NULL,
    expiry TIMESTAMPTZ NOT NULL
);
CREATE INDEX sessions_expiry_idx ON sessions (expiry);

-- migrate:down transaction:false
DROP INDEX CONCURRENTLY sessions_expiry_idx;
DROP TABLE sessions;
