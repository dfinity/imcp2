# OQL query surface

Some Internet Computer canisters expose **OQL** — a standard, self-describing,
agent-queryable surface over their data, carried by just two Candid **query**
methods that speak JSON-in-text. When `get_canister_candid` reports `oql: true` for a
canister, use the **`get_canister_oql_schema`** and **`canister_query`** (its `oql`
argument) tools to explore and query it rather than guessing bespoke per-question
methods. These wrap the two methods below, so you pass plain JSON (no Candid
escaping); this guide explains the dialect they speak.

## The two methods

- `schema : () -> (text) query` — a JSON catalogue of the data model. Fetch it
  once before querying:
  `{"entities":[{"name":..., "primaryKey":..., "fields":[{"name":..., "typeName":..., "role":...}]}]}`
  A field's `role` is either `"payload"` (a plain data column) or
  `{"edge":{"to":"<entity>"}}` (a link/foreign key to another entity). Use the
  entity `name`s here verbatim as your query's `"start"` — they are the schema's
  own names and are often PLURAL and different from the Candid types/methods (e.g.
  entity `bookings`, not a `Booking` type or a `getBookings` method). Don't guess
  them from the Candid interface.

> **Authentication.** Both `schema` and `execute` are gated by the CALLER's
> principal: an app shows a principal only the entities and rows it may see. So
> `get_canister_oql_schema` and `canister_query`'s `oql` path both **require** the app's
> canonical `derivation_origin` (from `open_app` / `resolve_app`) — an anonymous
> per-app read is disabled for now and is **rejected** with guidance to pass the
> origin, rather than silently returning an empty schema or zero rows. Passing the
> origin never hurts a public read either (the canister serves the request
> regardless of principal), so always pass it for app data.

- `execute : (text) -> (Result) query` — runs ONE JSON query object passed as
  the single text argument (`Result` is the paged rows record defined under
  **Result shape** below):
  `{"start":"<entity>", "where":<pred>, "groupBy":["f"], "aggregate":[{"fn":"count|sum|avg|min|max", "field":"f", "as":"out"}], "orderBy":[{"field":"f", "dir":"asc|desc"}], "offset":N, "limit":N, "select":["f"]}`
  Only `"start"` is required; a `count` aggregate needs no `"field"`. `canister_query`
  (its `oql` argument) sends this as a query call for you — it is the way to reach
  `execute`, since a Candid `method` query is rejected on a canister that exposes OQL.

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
`Cell = record { name : text; value : variant }`. `canister_query` decodes this into
`columns` + `rows` (one column per cell `name`) and renders a table for you; when
`has_more` is true, re-query with a higher `offset` to page. (If you read the raw
`execute` reply yourself, read cells **by name, never by position**.)

Prefer server-side `where`/`aggregate` over pulling whole tables into context.

## Presenting results to the user

Cells hold canonical, locale-neutral values — timestamps as **nanoseconds since the
Unix epoch (UTC)**, quantities in the app's stored unit (see `get_canister_api_doc`).
When you show them to the user, convert to their local conventions: their **time
zone** for dates/times, and their locale's **units** for the measures that split
US-customary vs metric — temperature (°C/°F), mass/weight (g, kg / oz, lb), length &
height (cm, m / in, ft), distance (km/mi), volume (mL, L / fl oz, US gal). Establish
the source unit first (the API doc, or the field name), then convert; keep the raw
value alongside the converted one when precision matters.

## Example

To find the first 10 employees whose last name contains "smith", returning only
their first and last names, call `canister_query` with:

- `canister_id`: the OQL canister's id
- `oql` (plain JSON — no Candid escaping):
  `{"start":"employee","where":{"icontains":{"field":"lastName","value":"smith"}},"select":["firstName","lastName"],"limit":10}`
- `derivation_origin`: the app's canonical origin (required for OQL)

`canister_query` returns the rows as a `firstName` / `lastName` table — it wraps the
`execute` query method and does the Candid text-arg escaping for you. (Reaching `execute`
through a Candid `method` query is rejected on an OQL canister, so use the `oql` argument.)
