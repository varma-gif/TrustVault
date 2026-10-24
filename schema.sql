-- TrustVault database schema (SQLite). Generated from models.py.
-- The app creates these tables itself on first start (db.create_all) and adds the
-- audit-log triggers that refuse UPDATE/DELETE. You do not need to run this by hand.

CREATE TABLE users (
	id INTEGER NOT NULL, 
	username VARCHAR(80) NOT NULL, 
	password_hash VARCHAR(255) NOT NULL, 
	role VARCHAR(20) NOT NULL, 
	active BOOLEAN NOT NULL, 
	session_version INTEGER NOT NULL, 
	created_at DATETIME NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT valid_user_role CHECK (role IN ('admin', 'owner', 'viewer'))
);

CREATE TABLE audit_events (
	id INTEGER NOT NULL, 
	actor_id INTEGER, 
	document_id INTEGER, 
	action VARCHAR(50) NOT NULL, 
	details TEXT, 
	created_at DATETIME NOT NULL, 
	ts VARCHAR(40) NOT NULL, 
	prev_hash VARCHAR(64) NOT NULL, 
	hash VARCHAR(64) NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(actor_id) REFERENCES users (id), 
	UNIQUE (prev_hash)
);

CREATE TABLE documents (
	id INTEGER NOT NULL, 
	name VARCHAR(200) NOT NULL, 
	category VARCHAR(100), 
	owner_id INTEGER NOT NULL, 
	storage_name VARCHAR(255) NOT NULL, 
	original_filename VARCHAR(255) NOT NULL, 
	mime_type VARCHAR(100) NOT NULL, 
	size_bytes INTEGER NOT NULL, 
	sha256 VARCHAR(64) NOT NULL, 
	version INTEGER NOT NULL, 
	created_at DATETIME NOT NULL, 
	updated_at DATETIME NOT NULL, 
	deleted_at DATETIME, 
	PRIMARY KEY (id), 
	FOREIGN KEY(owner_id) REFERENCES users (id), 
	UNIQUE (storage_name)
);

CREATE TABLE document_permissions (
	id INTEGER NOT NULL, 
	document_id INTEGER NOT NULL, 
	user_id INTEGER NOT NULL, 
	permission VARCHAR(10) NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT unique_document_user_permission UNIQUE (document_id, user_id), 
	CONSTRAINT valid_document_permission CHECK (permission IN ('read', 'edit')), 
	FOREIGN KEY(document_id) REFERENCES documents (id), 
	FOREIGN KEY(user_id) REFERENCES users (id)
);

-- Audit-log protection: the app installs these on startup.
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_events
       BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;;

CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_events
       BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;;

