const enc = new TextEncoder();

const json = (x, s = 200, h = {}) =>
  new Response(JSON.stringify(x), {
    status: s,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...h,
    },
  });

async function sha(s) {
  return [
    ...new Uint8Array(
      await crypto.subtle.digest("SHA-256", enc.encode(s))
    ),
  ]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function pbkdf(password, salt, iterations = 210000) {
  const k = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: enc.encode(salt),
      iterations,
    },
    k,
    256
  );

  return [...new Uint8Array(bits)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function cookie(req, name) {
  const m = (req.headers.get("cookie") || "").match(
    new RegExp("(?:^|; )" + name + "=([^;]*)")
  );

  return m ? decodeURIComponent(m[1]) : null;
}

async function auth(req, env) {
  const t = cookie(req, "rmm_session");

  if (!t) return null;

  const th = await sha(t);

  return env.DB.prepare(`
    SELECT
      u.id,
      u.username,
      u.role,
      s.csrf
    FROM sessions s
    JOIN users u
      ON u.id = s.user_id
    WHERE s.token_hash = ?
      AND u.active = 1
      AND s.expires_at > datetime('now')
  `)
    .bind(th)
    .first();
}

async function audit(env, u, a, d = "") {
  await env.DB.prepare(`
    INSERT INTO audit_log(
      user_id,
      action,
      details
    )
    VALUES(?,?,?)
  `)
    .bind(
      u?.id || null,
      a,
      d
    )
    .run();
}

function secureHeaders(r) {
  const h = new Headers(r.headers);

  h.set(
    "x-content-type-options",
    "nosniff"
  );

  h.set(
    "x-frame-options",
    "DENY"
  );

  h.set(
    "referrer-policy",
    "no-referrer"
  );

  h.set(
    "permissions-policy",
    "camera=(), microphone=(), geolocation=()"
  );

  h.set(
    "content-security-policy",
    "default-src 'self'; " +
      "style-src 'self' 'unsafe-inline'; " +
      "script-src 'self' 'unsafe-inline'; " +
      "img-src 'self' data:; " +
      "connect-src 'self'"
  );

  return new Response(r.body, {
    status: r.status,
    statusText: r.statusText,
    headers: h,
  });
}

export default {
  async fetch(req, env) {
    try {
      const u = new URL(req.url);
      const p = u.pathname;

      /*
      ============================
      HEALTH
      ============================
      */

      if (p === "/api/health") {
        return json({
          ok: true,
          app: "RMM Uchet",
          version: "0.4.1",
        });
      }

      /*
      ============================
      ПЕРВЫЙ ЗАПУСК
      ============================
      */

      if (
        p === "/api/setup" &&
        req.method === "POST"
      ) {
        const n = await env.DB.prepare(`
          SELECT COUNT(*) AS n
          FROM users
        `).first();

        if (Number(n?.n || 0) > 0) {
          return json(
            {
              error: "setup_done",
            },
            409
          );
        }

        const b = await req.json();

        const username =
          String(b?.username || "").trim();

        const password =
          String(b?.password || "");

        if (username.length < 3) {
          return json(
            {
              error: "username_min_3",
            },
            400
          );
        }

        if (password.length < 12) {
          return json(
            {
              error: "password_min_12",
            },
            400
          );
        }

        const salt =
          crypto.randomUUID();

        const hash =
          await pbkdf(
            password,
            salt
          );

        await env.DB.prepare(`
          INSERT INTO users(
            username,
            password_hash,
            role,
            active
          )
          VALUES(?,?,?,1)
        `)
          .bind(
            username,
            `pbkdf2$210000$${salt}$${hash}`,
            "owner"
          )
          .run();

        /*
        Аудит не должен ломать
        создание первого администратора.
        */

        try {
          await audit(
            env,
            null,
            "initial_setup",
            `owner:${username}`
          );
        } catch (auditError) {
          console.error(
            "Audit setup error:",
            auditError
          );
        }

        return json({
          ok: true,
          username,
        });
      }

      /*
      ============================
      ВХОД
      ============================
      */

      if (
        p === "/api/login" &&
        req.method === "POST"
      ) {
        const b = await req.json();

        const username =
          String(b?.username || "").trim();

        const password =
          String(b?.password || "");

        const row =
          await env.DB.prepare(`
            SELECT *
            FROM users
            WHERE username = ?
              AND active = 1
          `)
            .bind(username)
            .first();

        if (!row) {
          return json(
            {
              error: "bad_login",
            },
            401
          );
        }

        const parts =
          String(row.password_hash || "")
            .split("$");

        if (
          parts.length !== 4 ||
          parts[0] !== "pbkdf2"
        ) {
          return json(
            {
              error:
                "invalid_password_hash",
            },
            500
          );
        }

        const iterations =
          Number(parts[1]);

        const salt =
          parts[2];

        const want =
          parts[3];

        const got =
          await pbkdf(
            password,
            salt,
            iterations
          );

        if (got !== want) {
          try {
            await audit(
              env,
              row,
              "login_failed"
            );
          } catch (e) {
            console.error(
              "Audit login failure:",
              e
            );
          }

          return json(
            {
              error: "bad_login",
            },
            401
          );
        }

        const token =
          crypto.randomUUID() +
          crypto.randomUUID();

        const csrf =
          crypto.randomUUID();

        const th =
          await sha(token);

        await env.DB.prepare(`
          INSERT INTO sessions(
            token_hash,
            user_id,
            csrf,
            expires_at
          )
          VALUES(
            ?,
            ?,
            ?,
            datetime('now','+30 days')
          )
        `)
          .bind(
            th,
            row.id,
            csrf
          )
          .run();

        try {
          await audit(
            env,
            row,
            "login"
          );
        } catch (e) {
          console.error(
            "Audit login:",
            e
          );
        }

        return json(
          {
            ok: true,
            username: row.username,
            role: row.role,
            csrf,
          },
          200,
          {
            "set-cookie":
              `rmm_session=${encodeURIComponent(token)}; ` +
              "HttpOnly; Secure; SameSite=Strict; " +
              "Path=/; Max-Age=2592000",
          }
        );
      }

      /*
      ============================
      ПРОВЕРКА АВТОРИЗАЦИИ
      ============================
      */

      const me =
        await auth(req, env);

      if (
        p.startsWith("/api/") &&
        !me
      ) {
        return json(
          {
            error: "unauthorized",
          },
          401
        );
      }

      /*
      ============================
      ТЕКУЩИЙ ПОЛЬЗОВАТЕЛЬ
      ============================
      */

      if (p === "/api/me") {
        return json({
          username: me.username,
          role: me.role,
          csrf: me.csrf,
        });
      }

      /*
      ============================
      ПОЛУЧИТЬ ОБЩИЕ ДАННЫЕ
      ============================
      */

      if (
        p === "/api/state" &&
        req.method === "GET"
      ) {
        const r =
          await env.DB.prepare(`
            SELECT
              data,
              revision,
              updated_at
            FROM app_state
            WHERE id = 1
          `).first();

        if (!r) {
          return json({
            data: null,
            revision: 0,
          });
        }

        let parsed = null;

        try {
          parsed =
            JSON.parse(r.data);
        } catch (_) {
          parsed = null;
        }

        return json({
          data: parsed,
          revision: r.revision,
          updated_at: r.updated_at,
        });
      }

      /*
      ============================
      СОХРАНИТЬ ОБЩИЕ ДАННЫЕ
      ============================
      */

      if (
        p === "/api/state" &&
        req.method === "PUT"
      ) {
        if (
          req.headers.get(
            "x-csrf-token"
          ) !== me.csrf
        ) {
          return json(
            {
              error: "csrf",
            },
            403
          );
        }

        const b =
          await req.json();

        const cur =
          await env.DB.prepare(`
            SELECT revision
            FROM app_state
            WHERE id = 1
          `).first();

        if (
          cur &&
          Number(b.revision) !==
            Number(cur.revision)
        ) {
          return json(
            {
              error: "conflict",
              revision:
                cur.revision,
            },
            409
          );
        }

        const data =
          JSON.stringify(
            b.data
          );

        const rev =
          Number(
            cur?.revision || 0
          ) + 1;

        await env.DB.prepare(`
          INSERT INTO app_state(
            id,
            data,
            revision,
            updated_at
          )
          VALUES(
            1,
            ?,
            ?,
            CURRENT_TIMESTAMP
          )
          ON CONFLICT(id)
          DO UPDATE SET
            data =
              excluded.data,
            revision =
              excluded.revision,
            updated_at =
              CURRENT_TIMESTAMP
        `)
          .bind(
            data,
            rev
          )
          .run();

        try {
          await audit(
            env,
            me,
            "state_saved",
            `revision ${rev}`
          );
        } catch (e) {
          console.error(
            "Audit state:",
            e
          );
        }

        return json({
          ok: true,
          revision: rev,
        });
      }

      /*
      ============================
      СПИСОК ПОЛЬЗОВАТЕЛЕЙ
      ============================
      */

      if (
        p === "/api/users" &&
        req.method === "GET"
      ) {
        if (
          me.role !== "owner"
        ) {
          return json(
            {
              error: "forbidden",
            },
            403
          );
        }

        const r =
          await env.DB.prepare(`
            SELECT
              id,
              username,
              role,
              active,
              created_at
            FROM users
            ORDER BY id
          `).all();

        return json(
          r.results || []
        );
      }

      /*
      ============================
      СОЗДАНИЕ ПОЛЬЗОВАТЕЛЯ
      ============================
      */

      if (
        p === "/api/users" &&
        req.method === "POST"
      ) {
        if (
          me.role !== "owner"
        ) {
          return json(
            {
              error: "forbidden",
            },
            403
          );
        }

        if (
          req.headers.get(
            "x-csrf-token"
          ) !== me.csrf
        ) {
          return json(
            {
              error: "csrf",
            },
            403
          );
        }

        const b =
          await req.json();

        const username =
          String(
            b?.username || ""
          ).trim();

        const password =
          String(
            b?.password || ""
          );

        if (
          username.length < 3
        ) {
          return json(
            {
              error:
                "username_min_3",
            },
            400
          );
        }

        if (
          password.length < 12
        ) {
          return json(
            {
              error:
                "password_min_12",
            },
            400
          );
        }

        const salt =
          crypto.randomUUID();

        const hash =
          await pbkdf(
            password,
            salt
          );

        const role =
          b.role === "viewer"
            ? "viewer"
            : "editor";

        await env.DB.prepare(`
          INSERT INTO users(
            username,
            password_hash,
            role,
            active
          )
          VALUES(
            ?,
            ?,
            ?,
            1
          )
        `)
          .bind(
            username,
            `pbkdf2$210000$${salt}$${hash}`,
            role
          )
          .run();

        try {
          await audit(
            env,
            me,
            "user_created",
            username
          );
        } catch (e) {
          console.error(
            "Audit user:",
            e
          );
        }

        return json(
          {
            ok: true,
          },
          201
        );
      }

      /*
      ============================
      СТАТИЧЕСКОЕ ПРИЛОЖЕНИЕ
      ============================
      */

      const assetResponse =
        await env.ASSETS.fetch(req);

      return secureHeaders(
        assetResponse
      );

    } catch (e) {

      /*
      Теперь сервер НЕ скрывает
      настоящую причину ошибки.
      */

      console.error(
        "RMM SERVER ERROR:",
        e
      );

      return json(
        {
          error: "server_error",
          details: String(
            e?.message || e
          ),
        },
        500
      );
    }
  },
};
