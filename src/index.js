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

async function pbkdf(password, salt, iterations = 100000) {
  const key = await crypto.subtle.importKey(
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
    key,
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
  const token = cookie(req, "rmm_session");

  if (!token) return null;

  const tokenHash = await sha(token);

  return env.DB.prepare(`
    SELECT
      u.id,
      u.username,
      u.role,
      s.csrf
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ?
      AND u.active = 1
      AND s.expires_at > datetime('now')
  `)
    .bind(tokenHash)
    .first();
}

async function audit(env, user, action, details = "") {
  await env.DB.prepare(`
    INSERT INTO audit_log(
      user_id,
      action,
      details
    )
    VALUES(?,?,?)
  `)
    .bind(
      user?.id || null,
      action,
      details
    )
    .run();
}

function secureHeaders(response) {
  const headers = new Headers(response.headers);

  headers.set("x-content-type-options", "nosniff");
  headers.set("x-frame-options", "DENY");
  headers.set("referrer-policy", "no-referrer");

  headers.set(
    "permissions-policy",
    "camera=(), microphone=(), geolocation=()"
  );

  headers.set(
    "content-security-policy",
    "default-src 'self'; " +
      "style-src 'self' 'unsafe-inline'; " +
      "script-src 'self' 'unsafe-inline'; " +
      "img-src 'self' data:; " +
      "connect-src 'self'"
  );

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

export default {
  async fetch(req, env) {
    try {
      const url = new URL(req.url);
      const path = url.pathname;

      // Проверка сервера
      if (path === "/api/health") {
        return json({
          ok: true,
          app: "RMM Uchet",
          version: "0.4.2",
        });
      }

      // Первый запуск
      if (
        path === "/api/setup" &&
        req.method === "POST"
      ) {
        const count = await env.DB.prepare(`
          SELECT COUNT(*) AS n
          FROM users
        `).first();

        if (Number(count?.n || 0) > 0) {
          return json(
            { error: "setup_done" },
            409
          );
        }

        const body = await req.json();

        const username =
          String(body?.username || "").trim();

        const password =
          String(body?.password || "");

        if (username.length < 3) {
          return json(
            { error: "username_min_3" },
            400
          );
        }

        if (password.length < 12) {
          return json(
            { error: "password_min_12" },
            400
          );
        }

        const salt = crypto.randomUUID();

        const hash = await pbkdf(
          password,
          salt,
          100000
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
            `pbkdf2$100000$${salt}$${hash}`,
            "owner"
          )
          .run();

        // Ошибка журнала не должна ломать создание админа
        try {
          await audit(
            env,
            null,
            "initial_setup",
            `owner:${username}`
          );
        } catch (e) {
          console.error("Audit error:", e);
        }

        return json({
          ok: true,
          username,
        });
      }

      // Вход
      if (
        path === "/api/login" &&
        req.method === "POST"
      ) {
        const body = await req.json();

        const username =
          String(body?.username || "").trim();

        const password =
          String(body?.password || "");

        const user = await env.DB.prepare(`
          SELECT *
          FROM users
          WHERE username = ?
            AND active = 1
        `)
          .bind(username)
          .first();

        if (!user) {
          return json(
            { error: "bad_login" },
            401
          );
        }

        const parts =
          String(user.password_hash || "").split("$");

        if (
          parts.length !== 4 ||
          parts[0] !== "pbkdf2"
        ) {
          return json(
            { error: "invalid_password_hash" },
            500
          );
        }

        const iterations = Number(parts[1]);
        const salt = parts[2];
        const expectedHash = parts[3];

        if (
          !Number.isInteger(iterations) ||
          iterations < 1 ||
          iterations > 100000
        ) {
          return json(
            { error: "invalid_password_hash" },
            500
          );
        }

        const actualHash = await pbkdf(
          password,
          salt,
          iterations
        );

        if (actualHash !== expectedHash) {
          try {
            await audit(
              env,
              user,
              "login_failed"
            );
          } catch (_) {}

          return json(
            { error: "bad_login" },
            401
          );
        }

        const token =
          crypto.randomUUID() +
          crypto.randomUUID();

        const csrf = crypto.randomUUID();

        const tokenHash =
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
            tokenHash,
            user.id,
            csrf
          )
          .run();

        try {
          await audit(
            env,
            user,
            "login"
          );
        } catch (_) {}

        return json(
          {
            ok: true,
            username: user.username,
            role: user.role,
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

      // Всё ниже требует входа
      const me = await auth(req, env);

      if (
        path.startsWith("/api/") &&
        !me
      ) {
        return json(
          { error: "unauthorized" },
          401
        );
      }

      // Кто вошёл
      if (path === "/api/me") {
        return json({
          username: me.username,
          role: me.role,
          csrf: me.csrf,
        });
      }

      // Получить данные приложения
      if (
        path === "/api/state" &&
        req.method === "GET"
      ) {
        const row = await env.DB.prepare(`
          SELECT
            data,
            revision,
            updated_at
          FROM app_state
          WHERE id = 1
        `).first();

        if (!row) {
          return json({
            data: null,
            revision: 0,
          });
        }

        let data = null;

        try {
          data = JSON.parse(row.data);
        } catch (_) {
          data = null;
        }

        return json({
          data,
          revision: row.revision,
          updated_at: row.updated_at,
        });
      }

      // Сохранить данные приложения
      if (
        path === "/api/state" &&
        req.method === "PUT"
      ) {
        if (
          req.headers.get("x-csrf-token") !== me.csrf
        ) {
          return json(
            { error: "csrf" },
            403
          );
        }

        const body = await req.json();

        const current = await env.DB.prepare(`
          SELECT revision
          FROM app_state
          WHERE id = 1
        `).first();

        if (
          current &&
          Number(body.revision) !==
            Number(current.revision)
        ) {
          return json(
            {
              error: "conflict",
              revision: current.revision,
            },
            409
          );
        }

        const data =
          JSON.stringify(body.data);

        const revision =
          Number(current?.revision || 0) + 1;

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
            data = excluded.data,
            revision = excluded.revision,
            updated_at = CURRENT_TIMESTAMP
        `)
          .bind(
            data,
            revision
          )
          .run();

        try {
          await audit(
            env,
            me,
            "state_saved",
            `revision ${revision}`
          );
        } catch (_) {}

        return json({
          ok: true,
          revision,
        });
      }

      // Список пользователей
      if (
        path === "/api/users" &&
        req.method === "GET"
      ) {
        if (me.role !== "owner") {
          return json(
            { error: "forbidden" },
            403
          );
        }

        const result = await env.DB.prepare(`
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
          result.results || []
        );
      }

      // Создание дополнительных пользователей
      if (
        path === "/api/users" &&
        req.method === "POST"
      ) {
        if (me.role !== "owner") {
          return json(
            { error: "forbidden" },
            403
          );
        }

        if (
          req.headers.get("x-csrf-token") !== me.csrf
        ) {
          return json(
            { error: "csrf" },
            403
          );
        }

        const body = await req.json();

        const username =
          String(body?.username || "").trim();

        const password =
          String(body?.password || "");

        if (username.length < 3) {
          return json(
            { error: "username_min_3" },
            400
          );
        }

        if (password.length < 12) {
          return json(
            { error: "password_min_12" },
            400
          );
        }

        const salt = crypto.randomUUID();

        const hash = await pbkdf(
          password,
          salt,
          100000
        );

        const role =
          body.role === "viewer"
            ? "viewer"
            : "editor";

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
            `pbkdf2$100000$${salt}$${hash}`,
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
        } catch (_) {}

        return json(
          { ok: true },
          201
        );
      }

      // Файлы сайта
      const assetResponse =
        await env.ASSETS.fetch(req);

      return secureHeaders(assetResponse);

    } catch (e) {
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
