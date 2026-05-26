-- seed.sql — development seed data for Meridian-Canon local dev stack
-- Apply after schema migrations: ./dev/apply.sh --seed
-- All identifiers are synthetic (EXAMPLE-MATTER-001, user@example.com, etc.)

BEGIN;

-- Insert a stub matter for local development
INSERT INTO matters (matter_id, matter_ref, description, jurisdiction, status, created_at)
VALUES (
  '00000000-0000-0000-0000-000000000001',
  'EXAMPLE-MATTER-001',
  'Local development seed matter — not a real case',
  'US-WI',
  'active',
  now()
) ON CONFLICT DO NOTHING;

-- Insert a stub actor (system custodian)
INSERT INTO actors (actor_id, display_name, role, email, created_at)
VALUES (
  '00000000-0000-0000-0000-000000000001',
  'Dev Custodian',
  'owner',
  'dev@example.com',
  now()
) ON CONFLICT DO NOTHING;

COMMIT;
