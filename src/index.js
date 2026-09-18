const enc = new TextEncoder();

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...headers,
    },
  });

async function sha(text) {
  const buffer = await crypto.subtle.digest(
    "SHA-256",
    enc.encode(text)
  );

  return [...new Uint8Array(buffer)]
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

function getCookie(req, name) {
  const value = req.headers.get("cookie") || "";

  const match = value.match(
    new RegExp("(?:^|;\\s*)" + name + "=([^;]*)")
  );

  return match ? decodeURIComponent(match[1]) : null;
}

async function auth(req, env) {
  const token = getCookie(req, "rmm_session");

  if (!token) {
    return null;
  }

  const tokenHash = await sha(token);

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
    .bind(tokenHash)
    .first();
}

async function audit(env, user, action, details = "") {
  try {
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
  } catch (_) {
    // Журнал не должен ломать основную работу приложения.
  }
}

async function tableExists(env, tableName) {
  const result = await env.DB.prepare(`
    SELECT name
    FROM sqlite_master
    WHERE type='table'
      AND name=?
    LIMIT 1
  `)
    .bind(tableName)
    .first();

  return !!result;
}

async function databaseReady(env) {
  const required = [
    "users",
    "sessions",
    "audit_log",
    "app_state",
  ];

  for (const table of required) {
    if (!(await tableExists(env, table))) {
      return false;
    }
  }

  return true;
}

function securityHeaders(response) {
  const headers = new Headers(response.headers);

  headers.set(
    "x-content-type-options",
    "nosniff"
  );

  headers.set(
    "x-frame-options",
    "DENY"
  );

  headers.set(
    "referrer-policy",
    "no-referrer"
  );

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
      "connect-src 'self'; " +
      "frame-ancestors 'none'"
  );

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

async function handleRequest(req, env) {
  const url = new URL(req.url);
  const path = url.pathname;

  /* =========================
     HEALTH
  ========================= */

  if (path === "/api/health") {
    let db = false;

    try {
      db = await databaseReady(env);
    } catch (_) {}

    return json({
      ok: true,
      app: "RMM Uchet",
      version: "0.5.0",
      database: db,
    });
  }

  /* =========================
     SETUP STATUS
  ========================= */

  if (
    path === "/api/setup-status" &&
    req.method === "GET"
  ) {
    if (!(await databaseReady(env))) {
      return json(
        {
          setupRequired: true,
          databaseReady: false,
        },
        503
      );
    }

    const result = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM users"
    ).first();

    return json({
      setupRequired: Number(result?.n || 0) === 0,
      databaseReady: true,
    });
  }

  /* =========================
     INITIAL ADMIN
  ========================= */

  if (
    path === "/api/setup" &&
    req.method === "POST"
  ) {
    if (!(await databaseReady(env))) {
      return json(
        {
          error: "database_not_initialized",
        },
        503
      );
    }

    const count = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM users"
    ).first();

    if (Number(count?.n || 0) > 0) {
      return json(
        {
          error: "setup_done",
        },
        409
      );
    }

    let body;

    try {
      body = await req.json();
    } catch (_) {
      return json(
        {
          error: "invalid_json",
        },
        400
      );
    }

    const username =
      String(body.username || "").trim();

    const password =
      String(body.password || "");

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

    const salt = crypto.randomUUID();

    const iterations = 100000;

    const hash = await pbkdf(
      password,
      salt,
      iterations
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
        `pbkdf2$${iterations}$${salt}$${hash}`,
        "owner"
      )
      .run();

    await audit(
      env,
      null,
      "initial_setup",
      username
    );

    return json(
      {
        ok: true,
        username,
      },
      201
    );
  }

  /* =========================
     LOGIN
  ========================= */

  if (
    path === "/api/login" &&
    req.method === "POST"
  ) {
    if (!(await databaseReady(env))) {
      return json(
        {
          error: "database_not_initialized",
        },
        503
      );
    }

    let body;

    try {
      body = await req.json();
    } catch (_) {
      return json(
        {
          error: "invalid_json",
        },
        400
      );
    }

    const username =
      String(body.username || "").trim();

    const password =
      String(body.password || "");

    const row = await env.DB.prepare(`
      SELECT
        id,
        username,
        password_hash,
        role,
        active
      FROM users
      WHERE username=?
        AND active=1
      LIMIT 1
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
      String(row.password_hash || "").split("$");

    if (
      parts.length !== 4 ||
      parts[0] !== "pbkdf2"
    ) {
      return json(
        {
          error: "invalid_password_record",
        },
        500
      );
    }

    const iterations =
      Number(parts[1]);

    const salt =
      parts[2];

    const expectedHash =
      parts[3];

    if (
      !Number.isInteger(iterations) ||
      iterations < 1 ||
      iterations > 100000
    ) {
      return json(
        {
          error: "password_hash_not_supported"
        },
        500
      );
    }

    const actualHash = await pbkdf(
      password,
      salt,
      iterations
    );

    if (actualHash !== expectedHash) {
      await audit(
        env,
        row,
        "login_failed"
      );

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

    const tokenHash =
      await sha(token);

    /*
      Удаляем истёкшие сессии.
    */

    await env.DB.prepare(`
      DELETE FROM sessions
      WHERE expires_at <= datetime('now')
    `).run();

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
        row.id,
        csrf
      )
      .run();

    await audit(
      env,
      row,
      "login"
    );

    return json(
      {
        ok: true,
        username: row.username,
        role: row.role,
        csrf,
        redirect: "/",
      },
      200,
      {
        "set-cookie":
          `rmm_session=${encodeURIComponent(token)}; ` +
          "HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=2592000",
      }
    );
  }

  /* =========================
     LOGOUT
  ========================= */

  if (
    path === "/api/logout" &&
    req.method === "POST"
  ) {
    const token =
      getCookie(req, "rmm_session");

    if (token) {
      const tokenHash =
        await sha(token);

      try {
        await env.DB.prepare(
          "DELETE FROM sessions WHERE token_hash=?"
        )
          .bind(tokenHash)
          .run();
      } catch (_) {}
    }

    return json(
      {
        ok: true,
      },
      200,
      {
        "set-cookie":
          "rmm_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0",
      }
    );
  }

  /* =========================
     AUTH
  ========================= */

  let me = null;

  if (path.startsWith("/api/")) {
    me = await auth(req, env);

    if (!me) {
      return json(
        {
          error: "unauthorized",
        },
        401
      );
    }
  }

  /* =========================
     CURRENT USER
  ========================= */

  if (
    path === "/api/me" &&
    req.method === "GET"
  ) {
    return json({
      username: me.username,
      role: me.role,
      csrf: me.csrf,
    });
  }

  /* =========================
     APP STATE GET
  ========================= */

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
      WHERE id=1
    `).first();

    if (!row) {
      return json({
        data: null,
        revision: 0,
        updated_at: null,
      });
    }

    let data = null;

    try {
      data = JSON.parse(row.data);
    } catch (_) {}

    return json({
      data,
      revision: row.revision,
      updated_at: row.updated_at,
    });
  }

  /* =========================
     APP STATE SAVE
  ========================= */

  if (
    path === "/api/state" &&
    req.method === "PUT"
  ) {
    if (
      req.headers.get("x-csrf-token") !==
      me.csrf
    ) {
      return json(
        {
          error: "csrf",
        },
        403
      );
    }

    if (me.role === "viewer") {
      return json(
        {
          error: "forbidden",
        },
        403
      );
    }

    let body;

    try {
      body = await req.json();
    } catch (_) {
      return json(
        {
          error: "invalid_json",
        },
        400
      );
    }

    const current =
      await env.DB.prepare(`
        SELECT revision
        FROM app_state
        WHERE id=1
      `).first();

    const currentRevision =
      Number(current?.revision || 0);

    const suppliedRevision =
      Number(body.revision || 0);

    if (
      current &&
      suppliedRevision !== currentRevision
    ) {
      return json(
        {
          error: "conflict",
          revision: currentRevision,
        },
        409
      );
    }

    const serialized =
      JSON.stringify(body.data ?? null);

    const newRevision =
      currentRevision + 1;

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
        data=excluded.data,
        revision=excluded.revision,
        updated_at=CURRENT_TIMESTAMP
    `)
      .bind(
        serialized,
        newRevision
      )
      .run();

    await audit(
      env,
      me,
      "state_saved",
      `revision ${newRevision}`
    );

    return json({
      ok: true,
      revision: newRevision,
    });
  }

  /* =========================
     USERS LIST
  ========================= */

  if (
    path === "/api/users" &&
    req.method === "GET"
  ) {
    if (me.role !== "owner") {
      return json(
        {
          error: "forbidden",
        },
        403
      );
    }

    const result =
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
      result.results || []
    );
  }

  /* =========================
     CREATE USER
  ========================= */

  if (
    path === "/api/users" &&
    req.method === "POST"
  ) {
    if (me.role !== "owner") {
      return json(
        {
          error: "forbidden",
        },
        403
      );
    }

    if (
      req.headers.get("x-csrf-token") !==
      me.csrf
    ) {
      return json(
        {
          error: "csrf",
        },
        403
      );
    }

    let body;

    try {
      body = await req.json();
    } catch (_) {
      return json(
        {
          error: "invalid_json",
        },
        400
      );
    }

    const username =
      String(body.username || "").trim();

    const password =
      String(body.password || "");

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

    const existing =
      await env.DB.prepare(`
        SELECT id
        FROM users
        WHERE username=?
        LIMIT 1
      `)
        .bind(username)
        .first();

    if (existing) {
      return json(
        {
          error: "username_exists",
        },
        409
      );
    }

    const salt =
      crypto.randomUUID();

    const iterations =
      100000;

    const hash =
      await pbkdf(
        password,
        salt,
        iterations
      );

    let role = "editor";

    if (body.role === "viewer") {
      role = "viewer";
    }

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
        `pbkdf2$${iterations}$${salt}$${hash}`,
        role
      )
      .run();

    await audit(
      env,
      me,
      "user_created",
      username
    );

    return json(
      {
        ok: true,
      },
      201
    );
  }

  /* =========================
     STATIC APPLICATION
  ========================= */

  return env.ASSETS.fetch(req);
}

export default {
  async fetch(req, env) {
    try {
      const response =
        await handleRequest(req, env);

      return securityHeaders(response);
    } catch (error) {
      return securityHeaders(
        json(
          {
            error: "server_error",
            message:
              error instanceof Error
                ? error.message
                : String(error),
          },
          500
        )
      );
    }
  },
};
