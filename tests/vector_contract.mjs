#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = fileURLToPath(new URL("..", import.meta.url));
const pinPath = process.env.VECTOR_SOURCE_PIN ?? path.join(repositoryRoot, "vector-source-pin.json");
const productRoot = process.env.PRODUCT_ROOT;

if (!productRoot) {
  throw new Error("PRODUCT_ROOT must point to the pinned product lib-core checkout");
}

const pin = JSON.parse(readFileSync(pinPath, "utf8"));
if (!/^[0-9a-f]{40}$/.test(pin.revision)) {
  throw new Error("vector source revision must be a full commit SHA");
}
if (!/^[a-z][a-z0-9_]*$/.test(pin.schema) || !/^[a-z][a-z0-9_]*$/.test(pin.purpose)) {
  throw new Error("schema and purpose must be safe lower-snake-case identifiers");
}

const failures = [];
const requireContract = (condition, message) => {
  if (!condition) failures.push(message);
};
const productPath = (relativePath) => path.join(productRoot, relativePath);
const readProduct = (relativePath) => readFileSync(productPath(relativePath), "utf8");
const fileExists = (relativePath) => Boolean(relativePath) && existsSync(productPath(relativePath));

const manifest = JSON.parse(readProduct("embedding-contract/generation.json"));
const database = manifest.databaseFirst ?? {};
const codeFirst = manifest.codeFirst ?? {};
const dimensions = manifest.dimensions ?? {};
const desiredRelative = database.postgresDesiredState ?? database.postgres;
const queryRelative = database.postgresQuery;
const preflightRelative = database.postgresFamilyPreflight;
const reconcileRelative = database.postgresIndexReconciliation;
const adapterRelative = database.supabasePrivateAdapter;
const privilegeVerificationRelative = database.supabasePrivilegeVerification;

requireContract((dimensions.exactStorage ?? dimensions.storage) === pin.expected.exactDimensions,
  "manifest must declare 4100 exact storage dimensions");
requireContract(dimensions.indexedProjection === pin.expected.indexedDimensions,
  "manifest must declare a 4000-dimension indexed projection");
requireContract(pin.expected.fullPrecisionIndexCeiling === 2000,
  "test pin must record pgvector's vector HNSW ceiling of 2000 dimensions");
requireContract(pin.expected.halfPrecisionIndexCeiling === 4000,
  "test pin must record pgvector's halfvec HNSW ceiling of 4000 dimensions");
requireContract(dimensions.indexedProjection <= pin.expected.halfPrecisionIndexCeiling,
  "indexed projection must not exceed the halfvec HNSW ceiling");
requireContract(pin.expected.exactDimensions > pin.expected.fullPrecisionIndexCeiling,
  "the 4100-value exact authority must remain outside full-precision ANN indexing");
requireContract(dimensions.maximumSource === pin.expected.maximumSourceDimensions,
  "manifest must retain a 4096-dimension source ceiling");
requireContract(manifest.postgresFamily?.base?.includes("postgresql"),
  "manifest must target PostgreSQL");
requireContract(manifest.postgresFamily?.base?.includes("neon"),
  "manifest must target Neon");
requireContract(manifest.postgresFamily?.base?.includes("supabase"),
  "manifest must target Supabase");
requireContract(manifest.postgresFamily?.extensionSchema === "extensions",
  "pgvector must be installed in the extensions schema");
requireContract(manifest.postgresFamily?.extensionVersionPinned === false,
  "managed pgvector extension versions must not be pinned");
requireContract(manifest.migrationPlanning?.runtimeMayApply === false,
  "runtime startup must not apply migrations");
requireContract(manifest.migrationPlanning?.requiresShadowVerification === true,
  "migration planning must require shadow convergence");

requireContract(fileExists(desiredRelative), "product must publish PostgreSQL desired-state SQL");
requireContract(fileExists(queryRelative), "product must publish a named hybrid-search query");
requireContract(fileExists(preflightRelative), "product must publish a PostgreSQL-family capability preflight");
requireContract(fileExists(reconcileRelative), "product must publish idempotent model/index reconciliation SQL");
requireContract(fileExists(adapterRelative), "product must publish a private Supabase privilege adapter");
requireContract(fileExists(privilegeVerificationRelative), "product must publish Supabase privilege assertions");

const desired = fileExists(desiredRelative) ? readProduct(desiredRelative) : "";
const query = fileExists(queryRelative) ? readProduct(queryRelative) : "";
const typeSpec = fileExists(codeFirst.typeSpec) ? readProduct(codeFirst.typeSpec) : "";
const jsonSchema = fileExists(codeFirst.jsonSchema)
  ? JSON.parse(readProduct(codeFirst.jsonSchema))
  : {};
const projection = fileExists(codeFirst.ormProjection) ? readProduct(codeFirst.ormProjection) : "";

requireContract(/extensions\.vector\s*\(\s*4100\s*\)/i.test(desired),
  "exact table must use extensions.vector(4100)");
requireContract(/semantic_embedding_index/i.test(desired),
  "desired state must define a separate ANN projection table");
requireContract(/extensions\.halfvec\s*\(\s*4000\s*\)/i.test(desired),
  "ANN projection must use extensions.halfvec(4000)");
requireContract(/using\s+hnsw[\s\S]*halfvec_cosine_ops/i.test(desired),
  "ANN projection must use HNSW with halfvec_cosine_ops");
requireContract(!/binary_quantize/i.test(desired),
  "binary-quantized indexes must not replace the dense halfvec projection");
requireContract(/subvector[\s\S]*4100\s*-/i.test(desired),
  "desired state must reject non-zero padding tails");
requireContract(/nullif\s*\(\s*current_setting/i.test(desired),
  "RLS must fail closed for an unset or empty tenant setting");
requireContract(/semantic_embedding_index/i.test(query) && /semantic_embeddings/i.test(query),
  "hybrid search must join indexed candidates to exact embeddings");
requireContract(/halfvec/i.test(query) && /operator\s*\(\s*extensions\.<=>\s*\)/i.test(query),
  "hybrid search must schema-qualify pgvector cosine operators");
requireContract(!/binary_quantize/i.test(query),
  "hybrid search must not use binary quantization");
requireContract(/indexedDimensions\s*[:=][^\n]*4000/i.test(typeSpec),
  "TypeSpec must expose the 4000-dimension indexed projection");
requireContract(/storageDimensions\s*[:=][^\n]*4100/i.test(typeSpec),
  "TypeSpec must expose 4100 exact storage dimensions");

const maxItems = [];
const walkSchema = (value) => {
  if (Array.isArray(value)) {
    value.forEach(walkSchema);
  } else if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      if (key === "maxItems" && Number.isInteger(child)) maxItems.push(child);
      walkSchema(child);
    }
  }
};
walkSchema(jsonSchema);
requireContract(maxItems.includes(4100), "JSON Schema must validate the 4100-value exact vector");
requireContract(maxItems.includes(4000), "JSON Schema must validate the 4000-value indexed projection");
requireContract(/HalfVector/.test(projection), "Diesel projection must use pgvector HalfVector");
requireContract(/PgVector/.test(projection), "SeaORM projection must use PgVector for exact storage");
requireContract(/semantic_embedding_index/.test(projection),
  "ORM projection must identify the separate ANN table");

const pgEnvironment = { ...process.env, PGCONNECT_TIMEOUT: "10" };
const runPsql = (arguments_, input) => {
  const result = spawnSync("psql", ["-X", "--set", "ON_ERROR_STOP=1", ...arguments_], {
    env: pgEnvironment,
    encoding: "utf8",
    input,
  });
  if (result.status !== 0) {
    throw new Error(`psql failed:\n${result.stdout}${result.stderr}`);
  }
  return result.stdout.trim();
};
const scalar = (sql) => runPsql(["--tuples-only", "--no-align", "--quiet", "--command", sql]);

runPsql([], `
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN CREATE ROLE anon NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN CREATE ROLE authenticated NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN CREATE ROLE service_role NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vector_contract_app') THEN CREATE ROLE vector_contract_app NOLOGIN; END IF;
END
$$;
`);

if (fileExists(desiredRelative)) runPsql(["--file", productPath(desiredRelative)]);
if (fileExists(preflightRelative)) runPsql(["--file", productPath(preflightRelative)]);
if (fileExists(reconcileRelative)) runPsql(["--file", productPath(reconcileRelative)]);
if (fileExists(adapterRelative)) runPsql(["--file", productPath(adapterRelative)]);
if (fileExists(privilegeVerificationRelative)) runPsql(["--file", productPath(privilegeVerificationRelative)]);

const schema = pin.schema;
const purpose = pin.purpose;
const exactTable = `${schema}.semantic_embeddings`;
const indexedTable = `${schema}.semantic_embedding_index`;
const vectorSchema = scalar(`SELECT n.nspname FROM pg_extension e
  JOIN pg_namespace n ON n.oid = e.extnamespace WHERE e.extname = 'vector'`);
if (!/^[a-z][a-z0-9_]*$/.test(vectorSchema)) {
  throw new Error("installed pgvector schema is not a safe identifier");
}
requireContract(vectorSchema === "extensions", "pgvector must be installed in the extensions schema");

runPsql([], `
INSERT INTO ${exactTable}
  (tenant_id, entity_kind, entity_id, purpose, embedding_provider, model,
   original_dimensions, embedding, normalization, content_hash, search_text)
VALUES
  ('11111111-1111-4111-8111-111111111111', 'external_test', 'near-openai', '${purpose}',
   'openai', 'text-embedding-3-small', 1536,
   ${schema}.pad_embedding_4100(array_fill(0.01::real, ARRAY[1536])),
   'provider', repeat('a', 64), 'nearest semantic fixture'),
  ('11111111-1111-4111-8111-111111111111', 'external_test', 'far-openai', '${purpose}',
   'openai', 'text-embedding-3-small', 1536,
   ${schema}.pad_embedding_4100(array_fill(-0.01::real, ARRAY[1536])),
   'provider', repeat('b', 64), 'distant semantic fixture'),
  ('11111111-1111-4111-8111-111111111111', 'external_test', 'qwen-4096', '${purpose}',
   'qwen', 'Qwen/Qwen3-Embedding-8B', 4096,
   ${schema}.pad_embedding_4100(array_fill(0.001::real, ARRAY[4096])),
   'provider', repeat('c', 64), 'high dimensional fixture'),
  ('22222222-2222-4222-8222-222222222222', 'external_test', 'other-tenant', '${purpose}',
   'openai', 'text-embedding-3-small', 1536,
   ${schema}.pad_embedding_4100(array_fill(0.01::real, ARRAY[1536])),
   'provider', repeat('d', 64), 'tenant isolation fixture');
`);

requireContract(scalar(`SELECT ${vectorSchema}.vector_dims(embedding) || '|' ||
  ${vectorSchema}.vector_norm(${vectorSchema}.subvector(embedding, 1537, 2564))
  FROM ${exactTable} WHERE entity_id = 'near-openai'`) === "4100|0",
  "1536-value embeddings must store as vector(4100) with an exact zero tail");
requireContract(scalar(`SELECT ${vectorSchema}.vector_dims(embedding) || '|' ||
  ${vectorSchema}.vector_norm(${vectorSchema}.subvector(embedding, 4097, 4))
  FROM ${exactTable} WHERE entity_id = 'qwen-4096'`) === "4100|0",
  "4096-value embeddings must store as vector(4100) with four exact zeros");
requireContract(scalar(`SELECT entity_id FROM ${exactTable}
  WHERE tenant_id = '11111111-1111-4111-8111-111111111111'
    AND model = 'text-embedding-3-small'
  ORDER BY embedding OPERATOR(${vectorSchema}.<=>) ${schema}.pad_embedding_4100(array_fill(0.01::real, ARRAY[1536]))
  LIMIT 1`) === "near-openai",
  "exact cosine search must return the nearest fixture deterministically");

const candidateExists = scalar(`SELECT to_regclass('${indexedTable}') IS NOT NULL`) === "t";
requireContract(candidateExists, "database must materialize the separate ANN projection table");
if (candidateExists) {
  const indexedColumnType = scalar(`SELECT format_type(a.atttypid, a.atttypmod)
    FROM pg_attribute a
    WHERE a.attrelid = '${indexedTable}'::regclass
      AND a.attname = 'indexed_embedding' AND NOT a.attisdropped`);
  requireContract(indexedColumnType === `${vectorSchema}.halfvec(4000)`,
    "the ANN column must be a completely indexable halfvec(4000), not vector(4100)");
  requireContract(scalar(`SELECT count(*) FROM ${indexedTable}`) === "4",
    "trigger/reconciliation must maintain one ANN row per exact embedding");
  requireContract(scalar(`SELECT min(${vectorSchema}.vector_dims(indexed_embedding)) || '|' ||
    max(${vectorSchema}.vector_dims(indexed_embedding)) FROM ${indexedTable}`) === "4000|4000",
    "every ANN projection must contain exactly 4000 half-precision values");
  requireContract(scalar(`SELECT ${vectorSchema}.l2_norm(
      ${vectorSchema}.subvector(candidate.indexed_embedding, 1537, 2464))
    FROM ${indexedTable} AS candidate
    JOIN ${exactTable} AS exact USING (embedding_id)
    WHERE exact.entity_id = 'near-openai'`) === "0",
    "all 1536 OpenAI values must fit inside the indexable projection with a zero-only remainder");
  requireContract(scalar(`SELECT count(*) FROM pg_indexes
    WHERE schemaname = '${schema}' AND tablename = 'semantic_embeddings'
      AND indexdef ILIKE '%USING hnsw%'`) === "0",
    "the exact 4100-value table must not carry an ANN index");
  requireContract(Number(scalar(`SELECT count(*) FROM pg_indexes
    WHERE schemaname = '${schema}' AND tablename = 'semantic_embedding_index'
      AND indexdef ILIKE '%USING hnsw%' AND indexdef ILIKE '%halfvec_cosine_ops%'`)) >= 1,
    "the 4000-value candidate table must carry the halfvec HNSW index");
  requireContract(scalar(`WITH candidates AS (
      SELECT embedding_id
      FROM ${indexedTable}
      WHERE tenant_id = '11111111-1111-4111-8111-111111111111'
        AND embedding_space = 'openai:text-embedding-3-small:1536:provider'
        AND purpose = '${purpose}'
      ORDER BY indexed_embedding OPERATOR(${vectorSchema}.<=>)
        ${vectorSchema}.subvector(${schema}.pad_embedding_4100(array_fill(0.01::real, ARRAY[1536])), 1, 4000)::${vectorSchema}.halfvec(4000)
      LIMIT 2
    )
    SELECT exact.entity_id
    FROM candidates JOIN ${exactTable} AS exact USING (embedding_id)
    ORDER BY exact.embedding OPERATOR(${vectorSchema}.<=>) ${schema}.pad_embedding_4100(array_fill(0.01::real, ARRAY[1536]))
    LIMIT 1`) === "near-openai",
    "ANN candidate generation followed by exact reranking must preserve nearest-neighbor order");
  const plan = scalar(`SET enable_seqscan = off;
    EXPLAIN (COSTS OFF)
    SELECT embedding_id FROM ${indexedTable}
    ORDER BY indexed_embedding OPERATOR(${vectorSchema}.<=>)
      ${vectorSchema}.subvector(${schema}.pad_embedding_4100(array_fill(0.01::real, ARRAY[1536])), 1, 4000)::${vectorSchema}.halfvec(4000)
    LIMIT 2`);
  requireContract(/semantic_embedding_index_halfvec_hnsw_idx/i.test(plan),
    "forced ANN query plan must use the halfvec HNSW index");
}

runPsql([], `GRANT USAGE ON SCHEMA ${schema} TO vector_contract_app;
GRANT SELECT ON ALL TABLES IN SCHEMA ${schema} TO vector_contract_app;`);
requireContract(scalar(`BEGIN;
  SET LOCAL ROLE vector_contract_app;
  SET LOCAL app.tenant_id = '11111111-1111-4111-8111-111111111111';
  SELECT count(*) FROM ${exactTable};
  COMMIT;`) === "3",
  "RLS must expose only the selected tenant's rows to the application role");
try {
  requireContract(scalar(`BEGIN;
    SET LOCAL ROLE vector_contract_app;
    SET LOCAL app.tenant_id = '';
    SELECT count(*) FROM ${exactTable};
    COMMIT;`) === "0",
    "an empty tenant setting must fail closed with zero visible rows");
} catch (error) {
  failures.push(`an empty tenant setting must not raise a cast error: ${error.message}`);
}

const privileges = scalar(`SELECT concat_ws('|',
  has_schema_privilege('anon', '${schema}', 'USAGE'),
  has_schema_privilege('authenticated', '${schema}', 'USAGE'),
  has_table_privilege('service_role', '${exactTable}', 'SELECT'))`);
requireContract(privileges === "false|false|true" || privileges === "f|f|t",
  "Supabase browser roles must be denied while service_role can read exact embeddings");

if (failures.length > 0) {
  console.error(`vector/embedding conformance failed for ${pin.productRepository}@${pin.revision}:`);
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(`vector/embedding conformance passed for ${pin.productRepository}@${pin.revision}`);
