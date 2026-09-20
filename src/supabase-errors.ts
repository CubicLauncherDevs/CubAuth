/** Only expose machine-readable PostgreSQL/PostgREST codes, never upstream messages/details. */
export async function databaseCode(response: Response): Promise<string | undefined> {
  try {
    const body: unknown = await response.json();
    if (!body || typeof body !== 'object') return undefined;
    const code = (body as { code?: unknown }).code;
    return typeof code === 'string' && /^(?:PGRST\d{3}|[A-Z0-9]{5})$/.test(code) ? code : undefined;
  } catch {
    return undefined;
  }
}

export function databaseException(status: number, code?: string): { error: string; message: string } {
  if (code === 'PGRST202') return {
    error: 'DatabaseFunctionMissing',
    message: "Supabase cannot find the required CubAuth RPC. Apply supabase/migrations/202609200001_cubauth.sql in this project, then run NOTIFY pgrst, 'reload schema'; in the SQL Editor.",
  };
  if (['42P01', '3F000', '42883', '42703', 'PGRST205'].includes(code ?? '')) return {
    error: 'DatabaseSchemaMissing',
    message: 'The CubAuth database schema is missing or out of date. Check that the complete migration was applied successfully in the project specified by SUPABASE_URL.',
  };
  if (code === 'PGRST203') return {
    error: 'DatabaseFunctionAmbiguous',
    message: 'Supabase found multiple versions of the same RPC. Check the CubAuth function signatures against the migration and reload the PostgREST schema cache.',
  };
  if (code === 'PGRST106') return {
    error: 'DatabaseSchemaNotExposed',
    message: 'Enable the Supabase Data API and expose the public schema containing the cubauth_* RPCs. The private cubauth schema should remain unexposed.',
  };
  if (['PGRST301', 'PGRST302', 'PGRST303'].includes(code ?? '') || (status === 401 && code !== '42501')) return {
    error: 'SupabaseCredentialsInvalid',
    message: 'Supabase rejected SUPABASE_SERVICE_ROLE_KEY. Use the secret/service_role key from the same project as SUPABASE_URL and update the Cloudflare Worker secret.',
  };
  if (code === '42501' || status === 403) return {
    error: 'DatabasePermissionDenied',
    message: 'Supabase denied access to a CubAuth RPC. Check that SUPABASE_SERVICE_ROLE_KEY is a secret/service_role key, not an anon/publishable key, and that the migration granted RPC execution to service_role.',
  };
  if (status === 404) return {
    error: 'SupabaseEndpointNotFound',
    message: 'The Supabase Data API endpoint was not found. Check the Project URL, enable the Data API, and verify that the CubAuth migration is installed.',
  };
  if (status === 429) return {
    error: 'SupabaseRateLimited',
    message: 'Supabase is rate-limiting database requests. Wait before retrying and check the project limits.',
  };
  if (['PGRST000', 'PGRST001', 'PGRST002', 'PGRST003', '53300', '57P01'].includes(code ?? '') || status >= 500) return {
    error: 'SupabaseUnavailable',
    message: 'The Supabase database is temporarily unavailable. Check project status (including whether it is paused), connection limits and Supabase logs.',
  };
  return {
    error: 'DatabaseOperationFailed',
    message: 'Supabase rejected the database operation. Use details.operation, details.upstreamStatus and details.upstreamCode to locate the cause in the Worker and Supabase logs.',
  };
}
