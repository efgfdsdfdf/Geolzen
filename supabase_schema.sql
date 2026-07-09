-- =====================================================================
-- GEOLZEN DATABASE SCHEMA (SUPABASE POSTGRESQL)
-- Includes Row-Level Security (RLS) Policies and User Profile Triggers
-- =====================================================================

-- 1. EXTENSIONS
create extension if not exists "uuid-ossp";

-- 2. ORGANIZATIONS TABLE
create table public.organizations (
    id uuid default uuid_generate_v4() primary key,
    name text not null,
    created_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Enable RLS for Organizations
alter table public.organizations enable row level security;

-- 3. PROFILES TABLE (Tied to Supabase Auth)
create table public.profiles (
    id uuid references auth.users on delete cascade primary key,
    email text not null unique,
    full_name text,
    organization_id uuid references public.organizations(id) on delete set null,
    created_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Enable RLS for Profiles
alter table public.profiles enable row level security;

-- 4. TARGETS TABLE
create table public.targets (
    id uuid default uuid_generate_v4() primary key,
    organization_id uuid references public.organizations(id) on delete cascade not null,
    name text not null,
    type text not null check (type in ('domain', 'repository')),
    verified boolean default false not null,
    verification_method text check (verification_method in ('dns', 'file', 'oauth', 'dns-bypass')),
    verification_token text not null,
    created_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Enable RLS for Targets
alter table public.targets enable row level security;

-- 5. RULES OF ENGAGEMENT SIGNATURES
create table public.roe_signatures (
    id uuid default uuid_generate_v4() primary key,
    target_id uuid references public.targets(id) on delete cascade unique not null,
    signer_name text not null,
    signer_company text not null,
    signed_at timestamp with time zone default timezone('utc'::text, now()) not null,
    ip_address text
);

-- Enable RLS for ROE Signatures
alter table public.roe_signatures enable row level security;

-- 6. VULNERABILITIES TABLE
create table public.vulnerabilities (
    id uuid default uuid_generate_v4() primary key,
    target_id uuid references public.targets(id) on delete cascade not null,
    title text not null,
    severity text not null check (severity in ('critical', 'high', 'medium', 'low')),
    category text not null,
    description text not null,
    impact text not null,
    solution text not null,
    file_name text,
    original_code text,
    fixed_code text,
    remediated boolean default false not null,
    remediation_type text check (remediation_type in ('pr', 'config', 'policy')),
    created_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Enable RLS for Vulnerabilities
alter table public.vulnerabilities enable row level security;

-- 7. CHAT MESSAGES TABLE (Security Analyst Conversation)
create table public.chat_messages (
    id uuid default uuid_generate_v4() primary key,
    vulnerability_id uuid references public.vulnerabilities(id) on delete cascade not null,
    sender text not null check (sender in ('user', 'analyst')),
    message text not null,
    created_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Enable RLS for Chat Messages
alter table public.chat_messages enable row level security;


-- =====================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- Ensures data separation: users only access records inside their org
-- =====================================================================

-- Profiles Policies
create policy "Users can view their own profile."
    on public.profiles for select
    using ( auth.uid() = id );

create policy "Users can update their own profile."
    on public.profiles for update
    using ( auth.uid() = id );

-- Organizations Policies
create policy "Users can view their organization."
    on public.organizations for select
    using ( id = (select organization_id from public.profiles where id = auth.uid()) );

create policy "Admins can update organization info."
    on public.organizations for update
    using ( id = (select organization_id from public.profiles where id = auth.uid()) );

-- Targets Policies
create policy "Users can view targets within their organization."
    on public.targets for select
    using ( organization_id = (select organization_id from public.profiles where id = auth.uid()) );

create policy "Users can add targets to their organization."
    on public.targets for insert
    with check ( organization_id = (select organization_id from public.profiles where id = auth.uid()) );

create policy "Users can delete targets from their organization."
    on public.targets for delete
    using ( organization_id = (select organization_id from public.profiles where id = auth.uid()) );

-- ROE Signatures Policies
create policy "Users can view ROE signatures of their organization's targets."
    on public.roe_signatures for select
    using ( target_id in (
        select id from public.targets 
        where organization_id = (select organization_id from public.profiles where id = auth.uid())
    ) );

create policy "Users can sign ROE for their targets."
    on public.roe_signatures for insert
    with check ( target_id in (
        select id from public.targets 
        where organization_id = (select organization_id from public.profiles where id = auth.uid())
    ) );

-- Vulnerabilities Policies
create policy "Users can view vulnerabilities of their organization's targets."
    on public.vulnerabilities for select
    using ( target_id in (
        select id from public.targets 
        where organization_id = (select organization_id from public.profiles where id = auth.uid())
    ) );

create policy "Users can update remediation statuses for their vulnerabilities."
    on public.vulnerabilities for update
    using ( target_id in (
        select id from public.targets 
        where organization_id = (select organization_id from public.profiles where id = auth.uid())
    ) );

-- Chat Messages Policies
create policy "Users can view chat logs of their vulnerabilities."
    on public.chat_messages for select
    using ( vulnerability_id in (
        select v.id from public.vulnerabilities v
        join public.targets t on v.target_id = t.id
        where t.organization_id = (select organization_id from public.profiles where id = auth.uid())
    ) );

create policy "Users can post chat messages."
    on public.chat_messages for insert
    with check ( vulnerability_id in (
        select v.id from public.vulnerabilities v
        join public.targets t on v.target_id = t.id
        where t.organization_id = (select organization_id from public.profiles where id = auth.uid())
    ) );


-- =====================================================================
-- TRIGGERS & PROCEDURES (Auto-create profile from Auth Sign Up)
-- =====================================================================

-- Profile Creator Trigger Function
create or replace function public.handle_new_user()
returns trigger as $$
declare
    new_org_id uuid;
begin
    -- 1. Create a default organization for the new user
    insert into public.organizations (name)
    values (concat(new.email, '''s Workspace'))
    returning id into new_org_id;

    -- 2. Create the profile referencing the new organization
    insert into public.profiles (id, email, full_name, organization_id)
    values (
        new.id,
        new.email,
        coalesce(new.raw_user_meta_data->>'full_name', 'Security Operator'),
        new_org_id
    );
    return new;
end;
$$ language plpgsql security definer;

-- Trigger configuration
create or replace trigger on_auth_user_created
    after insert on auth.users
    for each row execute procedure public.handle_new_user();
