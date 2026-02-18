create table if not exists webhook_events (
  id bigserial primary key,
  created_at timestamptz not null default now(),
  event_name text not null,
  payload_json jsonb not null
);

create table if not exists licenses (
  id bigserial primary key,
  created_at timestamptz not null default now(),
  license_key text not null unique,
  email text not null,
  plan text not null,
  max_devices int not null,
  status text not null default 'active',
  expires_at timestamptz null,
  rally_purchase_at timestamptz null,
  rally_activation_deadline timestamptz null,
  rally_started_at timestamptz null,
  rally_expires_at timestamptz null,
  source text null,
  source_id text null
);
