# OQL query surface

Some Internet Computer canisters expose **OQL** — a standard, self-describing,
agent-queryable surface over their data, carried by just two Candid **query**
methods that speak JSON-in-text. When `get_candid` reports `oql: true` for a
canister, use the **`oql_schema`** and **`oql_query`** tools to explore and query
it rather than guessing bespoke per-question methods. Those tools wrap the two
methods below, so you pass plain JSON (no Candid escaping); this guide explains
the dialect they speak.

## The two methods

- `schema : () -> (text) query` — a JSON catalogue of the data model. Fetch it
  once before querying:
  `{"entities":[{"name":..., "primaryKey":..., "fields":[{"name":..., "typeName":..., "role":...}]}]}`
  A field's `role` is either `"payload"` (a plain data column) or
  `{"edge":{"to":"<entity>"}}` (a link/foreign key to another entity).

- `execute : (text) -> (Result) query` — runs ONE JSON query object passed as
  the single text argument (`Result` is the paged rows record defined under
  **Result shape** below):
  `{"start":"<entity>", "where":<pred>, "groupBy":["f"], "aggregate":[{"fn":"count|sum|avg|min|max", "field":"f", "as":"out"}], "orderBy":[{"field":"f", "dir":"asc|desc"}], "offset":N, "limit":N, "select":["f"]}`
  Only `"start"` is required; a `count` aggregate needs no `"field"`. `oql_query`
  sends this as a query call for you; if you instead drive `execute` through
  `call_canister`, it's a `query` method by convention (`is_query=true`).

## Predicates

Each predicate node has exactly ONE operator key:

- Comparison: `{"eq|ne|lt|le|gt|ge":{"field":"f","value":v}}`
- Set membership: `{"in":{"field":"f","value":[v, ...]}}`
- String: `{"contains|startsWith|endsWith|icontains":{"field":"f","value":"t"}}`
- Boolean: `{"and":[p, ...]}` | `{"or":[p, ...]}` | `{"not":p}`

The JSON type of `"value"` must match the field's `typeName`. A null field
fails every relation except `"ne"`.

## Edges (joins)

Dotted paths through declared edge fields are evaluated server-side in any field
position — e.g. `"manager.department.name"` — up to 4 hops. A dotted path into a
non-edge field traps. A reverse (one-to-many) traversal needs two queries chained
via `"in"`.

## Result shape

`record { hasMore : bool; rows : vec vec Cell }`, where
`Cell = record { name : text; value : variant }`. `oql_query` decodes this into
`columns` + `rows` (one column per cell `name`) and renders a table for you; when
`has_more` is true, re-query with a higher `offset` to page. (If you read the raw
`execute` reply yourself, read cells **by name, never by position**.)

Prefer server-side `where`/`aggregate` over pulling whole tables into context.

## Example

To find the first 10 employees whose last name contains "smith", returning only
their first and last names, call `oql_query` with:

- `canister_id`: the OQL canister's id
- `query` (plain JSON — no Candid escaping):
  `{"start":"employee","where":{"icontains":{"field":"lastName","value":"smith"}},"select":["firstName","lastName"],"limit":10}`

`oql_query` returns the rows as a `firstName` / `lastName` table. (The equivalent
low-level call is `call_canister` with `method="execute"`, `is_query=true`, and
that JSON escaped into a Candid text arg — `oql_query` saves you the escaping.)
