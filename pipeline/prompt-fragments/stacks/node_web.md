---
id: node_web
version: 1
covers: []
standards: ["cwe", "asvs5", "api-top10-2023"]
max_tokens: 1500
---
## Runtime and framework model
A JavaScript or TypeScript web application on Node.js (Express, Fastify, Koa, NestJS, Hapi,
Next.js API routes and server actions, Remix, Nuxt server routes) and often a browser front end
(React, Vue, Angular, Svelte). One event loop per process: a blocking regex or synchronous call
stalls every request. TypeScript types are erased at runtime and validate nothing.

## Trust and interface layer
- Entry points: route handlers, middleware, GraphQL resolvers, WebSocket/Socket.IO events,
  server actions, serverless handlers, and queue consumers.
- `req.query` and `req.body` may contain arrays and nested objects (`qs` parsing:
  `?a[$ne]=1`), not just strings.
- Authentication is middleware (Passport, express-session, JWT middleware, NestJS guards); route
  order and router mounting determine what it protects.
- Server-side rendering frameworks blur client and server: code in a server action is a public
  endpoint.
- Next.js middleware matchers and `config.matcher` patterns protect nothing on API routes
  outside them; edge and node runtimes may apply different checks.

## Idiomatic security mechanisms
- Schema validation of bodies (zod, Joi, ajv, class-validator) before use.
- Parameterized queries (`pg` `$1`, `mysql2` `?` placeholders, Prisma, Knex bindings).
- React/Vue/Angular escaping of text; DOMPurify for unavoidable HTML.
- helmet for headers and CSP; `csurf` replacements or SameSite cookies; `express-rate-limit`.
- `child_process.execFile`/`spawn` with argument arrays.
- `crypto.randomBytes`, `crypto.timingSafeEqual`, `bcrypt`/`argon2`.

## Stack-specific pitfalls
- Prototype pollution: deep merge, `lodash.merge`/`set` with user paths, `Object.assign` from
  parsed JSON with `__proto__` or `constructor.prototype` keys, leading to auth bypass or gadget
  code execution in template engines.
- NoSQL operator injection with Mongoose/MongoDB when bodies are passed as filters.
- `child_process.exec` with template strings; `eval`, `new Function`, `vm` (not a sandbox).
- `res.redirect(req.query.next)`; `res.sendFile` with user paths without `root`.
- `dangerouslySetInnerHTML`, `v-html`, `bypassSecurityTrustHtml`, `innerHTML` with user data.
- ReDoS in route or validation regexes on the single event loop.
- JWT libraries called with `decode` or without an `algorithms` list.
- `express.static` serving the project root or `.env`; source maps in production bundles.
- `NEXT_PUBLIC_`/`VITE_` variables leaking secrets into client bundles.

## Build and deployment facts to check
- `package-lock.json`/`pnpm-lock.yaml`/`yarn.lock` presence and `npm ci` use; install scripts.
- `NODE_ENV` in deployment and error-handler behaviour that differs by it.
- Bundler config: source maps, environment variable exposure, server versus client code split.
- `trust proxy` setting and the proxy in front; cookie `secure` and `sameSite` settings.
- Node.js version (permission model, `--experimental-policy`, default TLS behaviour).
