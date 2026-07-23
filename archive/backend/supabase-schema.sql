-- ═══════════════════════════════════════════════════════════════
--  KOR DA — Supabase Schema
--  Run this SQL in your Supabase Dashboard -> SQL Editor
-- ═══════════════════════════════════════════════════════════════

-- 1. Create Tables
CREATE TABLE waitlist (
  id uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
  email text UNIQUE NOT NULL,
  createdAt timestamp with time zone DEFAULT timezone('utc'::text, now()) NOT NULL
);

CREATE TABLE contacts (
  id uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
  name text,
  email text,
  subject text,
  message text,
  createdAt timestamp with time zone DEFAULT timezone('utc'::text, now()) NOT NULL
);

CREATE TABLE applications (
  id text PRIMARY KEY,
  status text DEFAULT 'pending',
  host jsonb NOT NULL,
  property jsonb NOT NULL,
  createdAt timestamp with time zone DEFAULT timezone('utc'::text, now()) NOT NULL,
  approvedAt timestamp with time zone,
  rejectedAt timestamp with time zone,
  rejectionReason text
);

CREATE TABLE listings (
  id text PRIMARY KEY,
  status text DEFAULT 'approved',
  host jsonb NOT NULL,
  city text,
  type text,
  price numeric,
  featured boolean DEFAULT false,
  createdAt timestamp with time zone DEFAULT timezone('utc'::text, now()) NOT NULL,
  maxGuests integer,
  address text,
  description text,
  category text,
  photos jsonb,
  amenities jsonb
);

CREATE TABLE bookings (
  id text PRIMARY KEY,
  listingId text REFERENCES listings(id),
  guestId uuid REFERENCES auth.users(id),
  guestPhone text,
  checkIn text,
  checkOut text,
  guests integer,
  nights integer,
  totalAmount numeric,
  commission numeric,
  hostPayout numeric,
  status text DEFAULT 'pending_payment',
  createdAt timestamp with time zone DEFAULT timezone('utc'::text, now()) NOT NULL,
  checkedInAt timestamp with time zone,
  payoutAt timestamp with time zone,
  disputeReason text,
  disputeAt timestamp with time zone
);

-- 2. Create Storage Bucket for Uploads
insert into storage.buckets (id, name, public) values ('uploads', 'uploads', true);

-- 3. Storage Security Rules (Allow public read, allow anon insert for applications)
create policy "Public Access" on storage.objects for select using ( bucket_id = 'uploads' );
create policy "Anon Insert" on storage.objects for insert with check ( bucket_id = 'uploads' );
