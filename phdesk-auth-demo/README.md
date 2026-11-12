# PHdesk Auth Demo: Create account, Login, Logout

Simpleng web app para matutunan kung paano gumagana ang create account, login at logout,
at kung paano nase-save nang safe ang password sa database.

- **Server:** Cloudflare Workers (`src/index.js`)
- **Database:** Cloudflare D1 (SQLite), tables sa `schema.sql`
- **Password:** salt + hash (PBKDF2-SHA256, 100,000 iterations); hindi kailanman sine-save ang totoong password
- **Session:** random token sa `HttpOnly` cookie; SHA-256 lang ng token ang nasa database

## Paano patakbuhin (local, libre, walang Cloudflare account)
Kailangan: Node.js 20 o mas bago.

```bash
npm install          # ini-install ang wrangler
npm run db:init      # gagawa ng users at sessions tables sa local D1
npm run dev          # bubuksan ang app sa http://localhost:8787
```

Silipin ang laman ng database habang tumatakbo:
```bash
npm run users        # SELECT * FROM users  (makikita mo ang password_hash)
npm run sessions     # SELECT * FROM sessions
```

## Ang mga route
| Route | Ginagawa |
|---|---|
| `GET /` | Home, para lang sa naka-login (kung hindi, papunta sa `/login`) |
| `GET /signup`, `POST /signup` | Create account: i-hash ang password, i-save ang user, simulan ang session |
| `GET /login`, `POST /login` | Login: i-hash ulit ang tinype na password gamit ang parehong salt, at ikumpara |
| `POST /logout` | Logout: burahin ang session sa database at ang cookie |

## Paalala bago i-deploy
- Sa Cloudflare Workers, **100,000** ang pinakamataas na PBKDF2 iterations. Ang rekomendasyon ng OWASP
  ay 600,000+ (o Argon2id), kaya pang-aral ang setting na ito.
- Sa **Free plan**, 10 ms lang ang CPU bawat request, at mga 23 ms ang 100k PBKDF2, kaya puwedeng mag-error 1102.
  Gumamit ng Workers Paid plan, o gawin ang password hashing sa ibang server.
- Kapag ide-deploy: `npx wrangler d1 create auth-demo-db`, ilagay ang totoong `database_id` sa `wrangler.jsonc`,
  `npx wrangler d1 execute auth-demo-db --remote --file=./schema.sql`, tapos `npx wrangler deploy`.
