import { Pool, QueryResult, QueryResultRow } from 'pg';
import { env } from '../config/env';

const isSupabase = env.DATABASE_URL.includes('supabase.com') || env.DATABASE_URL.includes('pooler');
const isProduction = env.NODE_ENV === 'production';

// Note on TLS/SSL:
// Supabase pooler connections require SSL. rejectUnauthorized is set to false for internal tool scope.
// TODO: For strict certificate validation in production, download the Supabase CA certificate
// and pass ssl: { ca: fs.readFileSync('path/to/prod-ca.crt'), rejectUnauthorized: true } or set PGSSLROOTCERT.
export const pool = new Pool({
  connectionString: env.DATABASE_URL,
  ssl: isSupabase || isProduction ? { rejectUnauthorized: false } : undefined
});

export async function query<T extends QueryResultRow = QueryResultRow>(
  text: string,
  params?: unknown[]
): Promise<QueryResult<T>> {
  return pool.query<T>(text, params);
}

export async function testDbConnection(): Promise<void> {
  try {
    await query('SELECT 1');
    console.log('Database connected successfully (SELECT 1 passed)');
  } catch (error) {
    console.error('Database connection failed:', error);
    throw error;
  }
}
