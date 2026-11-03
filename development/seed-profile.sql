-- Disposable development/conformance database only.
INSERT INTO users(id,trap_id) VALUES ('11111111-1111-4111-8111-111111111111','testuser') ON CONFLICT DO NOTHING;
