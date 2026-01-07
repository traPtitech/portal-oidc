-- OIDCクライアント
CREATE TABLE clients (
  client_id UUID,
  client_secret_hash VARCHAR(255),
  name VARCHAR(255),
  client_type VARCHAR(20),
  redirect_uris JSONB,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT clients_pkey PRIMARY KEY (client_id)
);

CREATE OR REPLACE FUNCTION update_clients_updated_at_func()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_clients_updated_at
  BEFORE UPDATE ON clients
  FOR EACH ROW
  EXECUTE FUNCTION update_clients_updated_at_func();
