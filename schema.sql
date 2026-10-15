-- 1. SCHEMAS
-- =========================================================================
CREATE SCHEMA IF NOT EXISTS private;

-- =========================================================================
-- 2. ENUMS
-- =========================================================================
DO $$ BEGIN
  CREATE TYPE public.app_role AS ENUM ('admin', 'analyst', 'user');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE public.analysis_status AS ENUM ('pending', 'processing', 'completed', 'failed');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE public.trust_verdict AS ENUM (
    'authentic','authentic_probable','suspect','manipulated','falsified','unknown'
  );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- =========================================================================
-- 3. FONCTIONS UTILITAIRES
-- =========================================================================
CREATE OR REPLACE FUNCTION public.touch_updated_at()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$ BEGIN NEW.updated_at = now(); RETURN NEW; END; $$;

CREATE OR REPLACE FUNCTION public.has_role(_user_id uuid, _role public.app_role)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.user_roles WHERE user_id = _user_id AND role = _role
  );
$$;

-- Alias private.has_role pour matcher les policies de Lovable Cloud
CREATE OR REPLACE FUNCTION private.has_role(_user_id uuid, _role public.app_role)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.user_roles WHERE user_id = _user_id AND role = _role
  );
$$;

CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  INSERT INTO public.profiles (id, full_name)
  VALUES (NEW.id, COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.email));
  INSERT INTO public.user_roles (user_id, role) VALUES (NEW.id, 'user');
  RETURN NEW;
END; $$;

CREATE OR REPLACE FUNCTION public.log_audit_event(
  _action text, _resource_type text DEFAULT NULL, _resource_id text DEFAULT NULL,
  _metadata jsonb DEFAULT '{}'::jsonb
) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE _uid uuid := auth.uid(); _id uuid;
  _allowed text[] := ARRAY['file.uploaded','analysis.completed','analysis.failed','comparison.saved'];
BEGIN
  IF _uid IS NULL THEN RAISE EXCEPTION 'not authenticated'; END IF;
  IF _action IS NULL OR NOT (_action = ANY(_allowed)) THEN RAISE EXCEPTION 'invalid audit action'; END IF;
  INSERT INTO public.audit_logs (user_id, action, resource_type, resource_id, metadata)
  VALUES (_uid, _action, _resource_type, _resource_id, COALESCE(_metadata,'{}'::jsonb))
  RETURNING id INTO _id;
  RETURN _id;
END; $$;

-- =========================================================================
-- 4. TABLES
-- =========================================================================

-- profiles
CREATE TABLE IF NOT EXISTS public.profiles (
  id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  full_name text,
  organization text,
  avatar_url text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE ON public.profiles TO authenticated;
GRANT ALL ON public.profiles TO service_role;
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Users view own profile" ON public.profiles;
CREATE POLICY "Users view own profile" ON public.profiles FOR SELECT TO authenticated USING (auth.uid() = id);
DROP POLICY IF EXISTS "Users insert own profile" ON public.profiles;
CREATE POLICY "Users insert own profile" ON public.profiles FOR INSERT TO authenticated WITH CHECK (auth.uid() = id);
DROP POLICY IF EXISTS "Users update own profile" ON public.profiles;
CREATE POLICY "Users update own profile" ON public.profiles FOR UPDATE TO authenticated USING (auth.uid() = id);
DROP POLICY IF EXISTS "Admins view all profiles" ON public.profiles;
CREATE POLICY "Admins view all profiles" ON public.profiles FOR SELECT TO authenticated USING (private.has_role(auth.uid(), 'admin'));

-- user_roles
CREATE TABLE IF NOT EXISTS public.user_roles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  role public.app_role NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(user_id, role)
);
GRANT SELECT ON public.user_roles TO authenticated;
GRANT ALL ON public.user_roles TO service_role;
ALTER TABLE public.user_roles ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Users view own roles" ON public.user_roles;
CREATE POLICY "Users view own roles" ON public.user_roles FOR SELECT TO authenticated USING (auth.uid() = user_id);
DROP POLICY IF EXISTS "Admins view all roles" ON public.user_roles;
CREATE POLICY "Admins view all roles" ON public.user_roles FOR SELECT TO authenticated USING (private.has_role(auth.uid(),'admin'));
DROP POLICY IF EXISTS "Admins insert roles" ON public.user_roles;
CREATE POLICY "Admins insert roles" ON public.user_roles FOR INSERT TO authenticated WITH CHECK (public.has_role(auth.uid(),'admin'));
DROP POLICY IF EXISTS "Admins update roles" ON public.user_roles;
CREATE POLICY "Admins update roles" ON public.user_roles FOR UPDATE TO authenticated USING (public.has_role(auth.uid(),'admin'));
DROP POLICY IF EXISTS "Admins delete roles" ON public.user_roles;
CREATE POLICY "Admins delete roles" ON public.user_roles FOR DELETE TO authenticated USING (public.has_role(auth.uid(),'admin'));

-- analyses
CREATE TABLE IF NOT EXISTS public.analyses (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  filename text NOT NULL,
  file_type text NOT NULL,
  file_size bigint NOT NULL,
  mime_type text,
  sha256 text,
  sha512 text,
  storage_path text,
  status public.analysis_status NOT NULL DEFAULT 'pending',
  verdict public.trust_verdict NOT NULL DEFAULT 'unknown',
  trust_score integer CHECK (trust_score BETWEEN 0 AND 100),
  scores jsonb NOT NULL DEFAULT '{}'::jsonb,
  evidence jsonb NOT NULL DEFAULT '[]'::jsonb,
  anomalies jsonb NOT NULL DEFAULT '[]'::jsonb,
  error_message text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  evidence_v2 jsonb NOT NULL DEFAULT '[]'::jsonb,
  consistency_score integer,
  reliability_score integer,
  document_profile text,
  heatmap jsonb
);
CREATE INDEX IF NOT EXISTS idx_analyses_user_created ON public.analyses(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_analyses_status ON public.analyses(status);
CREATE INDEX IF NOT EXISTS idx_analyses_verdict ON public.analyses(verdict);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.analyses TO authenticated;
GRANT ALL ON public.analyses TO service_role;
ALTER TABLE public.analyses ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Users view own analyses" ON public.analyses;
CREATE POLICY "Users view own analyses" ON public.analyses FOR SELECT TO authenticated USING (auth.uid() = user_id);
DROP POLICY IF EXISTS "Users create own analyses" ON public.analyses;
CREATE POLICY "Users create own analyses" ON public.analyses FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);
DROP POLICY IF EXISTS "Users update own analyses" ON public.analyses;
CREATE POLICY "Users update own analyses" ON public.analyses FOR UPDATE TO authenticated USING (auth.uid() = user_id);
DROP POLICY IF EXISTS "Users delete own analyses" ON public.analyses;
CREATE POLICY "Users delete own analyses" ON public.analyses FOR DELETE TO authenticated USING (auth.uid() = user_id);
DROP POLICY IF EXISTS "Admins view all analyses" ON public.analyses;
CREATE POLICY "Admins view all analyses" ON public.analyses FOR SELECT TO authenticated USING (private.has_role(auth.uid(),'admin'));

-- comparisons
CREATE TABLE IF NOT EXISTS public.comparisons (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  reference_filename text NOT NULL,
  candidate_filename text NOT NULL,
  reference_sha256 text NOT NULL,
  candidate_sha256 text NOT NULL,
  similarity_score integer NOT NULL,
  verdict text NOT NULL,
  diff jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.comparisons TO authenticated;
GRANT ALL ON public.comparisons TO service_role;
ALTER TABLE public.comparisons ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Users manage their own comparisons" ON public.comparisons;
CREATE POLICY "Users manage their own comparisons" ON public.comparisons FOR ALL
  USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
DROP TRIGGER IF EXISTS touch_comparisons_updated_at ON public.comparisons;
CREATE TRIGGER touch_comparisons_updated_at BEFORE UPDATE ON public.comparisons
  FOR EACH ROW EXECUTE FUNCTION public.touch_updated_at();

-- audit_logs
CREATE TABLE IF NOT EXISTS public.audit_logs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  action text NOT NULL,
  resource_type text,
  resource_id text,
  ip_address text,
  user_agent text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_user_created ON public.audit_logs(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action ON public.audit_logs(action);
GRANT SELECT ON public.audit_logs TO authenticated;
GRANT ALL ON public.audit_logs TO service_role;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Users view own audit" ON public.audit_logs;
CREATE POLICY "Users view own audit" ON public.audit_logs FOR SELECT TO authenticated USING (auth.uid() = user_id);
DROP POLICY IF EXISTS "Admins view all audit" ON public.audit_logs;
CREATE POLICY "Admins view all audit" ON public.audit_logs FOR SELECT TO authenticated USING (private.has_role(auth.uid(),'admin'));

-- Trigger auth : nouvel utilisateur → profile + role
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- =========================================================================
-- 5. STATE TABLE POUR LA SYNCHRONISATION (miroir Lovable → Externe)
-- =========================================================================
CREATE TABLE IF NOT EXISTS public.mirror_sync_state (
  table_name text PRIMARY KEY,
  last_synced_at timestamptz NOT NULL DEFAULT '1970-01-01T00:00:00Z',
  last_run_at timestamptz,
  last_row_count integer DEFAULT 0,
  last_error text
);
GRANT ALL ON public.mirror_sync_state TO service_role;
ALTER TABLE public.mirror_sync_state ENABLE ROW LEVEL SECURITY;
-- Aucune policy → seul service_role peut lire/écrire (bypass RLS)

-- =========================================================================
-- 6. STORAGE BUCKET (evidence, privé)
-- =========================================================================
INSERT INTO storage.buckets (id, name, public)
VALUES ('evidence','evidence', false)
ON CONFLICT (id) DO NOTHING;

DROP POLICY IF EXISTS "Users read own evidence" ON storage.objects;
CREATE POLICY "Users read own evidence" ON storage.objects FOR SELECT TO authenticated
  USING (bucket_id = 'evidence' AND auth.uid()::text = (storage.foldername(name))[1]);
DROP POLICY IF EXISTS "Users insert own evidence" ON storage.objects;
CREATE POLICY "Users insert own evidence" ON storage.objects FOR INSERT TO authenticated
  WITH CHECK (bucket_id = 'evidence' AND auth.uid()::text = (storage.foldername(name))[1]);
DROP POLICY IF EXISTS "Users update own evidence" ON storage.objects;
CREATE POLICY "Users update own evidence" ON storage.objects FOR UPDATE TO authenticated
  USING (bucket_id = 'evidence' AND auth.uid()::text = (storage.foldername(name))[1]);
DROP POLICY IF EXISTS "Users delete own evidence" ON storage.objects;
CREATE POLICY "Users delete own evidence" ON storage.objects FOR DELETE TO authenticated
  USING (bucket_id = 'evidence' AND auth.uid()::text = (storage.foldername(name))[1]);
