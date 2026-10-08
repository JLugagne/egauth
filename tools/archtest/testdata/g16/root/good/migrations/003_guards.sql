DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_type WHERE typname = 'x') THEN CREATE TYPE x AS ENUM ('a'); END IF; END $$;
DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'a' AND column_name IN ('b', 'c')) THEN ALTER TABLE a ADD COLUMN b int; END IF; END $$;
DO $$ BEGIN CREATE TYPE y AS ENUM ('a'); EXCEPTION WHEN duplicate_object OR duplicate_table THEN NULL; END $$;
CREATE TABLE IF NOT EXISTS g (id int GENERATED ALWAYS AS (1) STORED, x text DEFAULT lower('A')) WITH (fillfactor = 90);
DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.relname = 'a') THEN NULL; END IF; END $$;
