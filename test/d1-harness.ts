import { DatabaseSync, type SQLInputValue } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { fileURLToPath, URL as NodeUrl } from 'node:url';

/** Real SQLite with D1's asynchronous interface and transactional batch semantics. */
export function sqliteD1() {
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec(readFileSync(fileURLToPath(new NodeUrl('../migrations/0001_discord.sql', import.meta.url)), 'utf8'));
  class Statement {
    constructor(
      readonly sql: string,
      readonly values: SQLInputValue[] = [],
    ) {}
    bind(...values: SQLInputValue[]) {
      return new Statement(this.sql, values);
    }
    execute() {
      const stmt = sqlite.prepare(this.sql);
      const results = stmt.columns().length ? stmt.all(...this.values).map((row) => ({ ...row })) : [];
      let changes = 0;
      if (!stmt.columns().length) changes = Number(stmt.run(...this.values).changes);
      else if (!/^\s*SELECT/i.test(this.sql))
        changes = Number((sqlite.prepare('SELECT changes() AS n').get() as { n: number }).n);
      return { results, success: true, meta: { changes } };
    }
    async first<T>(column?: string): Promise<T | null> {
      const row = this.execute().results[0];
      return (row ? (column ? row[column] : row) : null) as T | null;
    }
    async all<T>() {
      return this.execute() as unknown as D1Result<T>;
    }
    async run() {
      return this.execute();
    }
  }
  const db = {
    prepare: (sql: string) => new Statement(sql),
    async batch(statements: Statement[]) {
      sqlite.exec('BEGIN IMMEDIATE');
      try {
        const results = statements.map((stmt) => stmt.execute());
        sqlite.exec('COMMIT');
        return results;
      } catch (error) {
        sqlite.exec('ROLLBACK');
        throw error;
      }
    },
    async exec(sql: string) {
      sqlite.exec(sql);
      return { count: 1, duration: 0 };
    },
  } as unknown as D1Database;
  return { db, sqlite, close: () => sqlite.close() };
}
