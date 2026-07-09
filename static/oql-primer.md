# OQL query surface

Some Internet Computer canisters expose **OQL** — a standard, self-describing,
agent-queryable surface over their data, carried by just two Candid **query**
methods that speak JSON-in-text. When `get_candid` reports `oql: true` for a
canister, use this guide to query it via `call_canister` (with `is_query=true`)
rather than guessing bespoke per-question methods.

## The two methods

- `schema : () -> (text) query` — a JSON catalogue of the data model. Fetch it
  once before querying:
  `{"entities":[{"name":..., "primaryKey":..., "fields":[{"name":..., "typeName":..., "role":...}]}]}`
  A field's `role` is either `"payload"` (a plain data column) or
  `{"edge":{"to":"<entity>"}}` (a link/foreign key to another entity).

- `execute : (text) -> (Result) query` — runs ONE JSON query object passed as
  the single text argument:
  `{"start":"<entity>", "where":<pred>, "groupBy":["f"], "aggregate":[{"fn":"count|sum|avg|min|max", "field":"f", "as":"out"}], "orderBy":[{"field":"f", "dir":"asc|desc"}], "offset":N, "limit":N, "select":["f"]}`
  Only `"start"` is required; a `count` aggregate needs no `"field"`.

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
`Cell = record { name : text; value : variant }`. Read cells **by name, never by
position**. When `hasMore = true`, page on by increasing `offset`.

Prefer server-side `where`/`aggregate` over pulling whole tables into context.

## Example

To find the first 10 employees whose last name contains "smith", returning only
their first and last names:

- tool: `call_canister`
- `canister_id`: the OQL canister's id
- `method`: `execute`
- `is_query`: `true`
- `args`:
  `("{\"start\":\"employee\",\"where\":{\"icontains\":{\"field\":\"lastName\",\"value\":\"smith\"}},\"select\":[\"firstName\",\"lastName\"],\"limit\":10}")`
