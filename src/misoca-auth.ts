import type {
  AuthRequest,
  OAuthHelpers,
} from "@cloudflare/workers-oauth-provider";

export type MisocaProps = {
  accessToken: string;
  refreshToken?: string;
  expiresAt?: number;
  userId: string;
  userLabel: string;
};

type MisocaEnv = Env & {
  OAUTH_KV: KVNamespace;
  OAUTH_PROVIDER: OAuthHelpers;
  MISOCA_CLIENT_ID: string;
  MISOCA_CLIENT_SECRET: string;
  COOKIE_ENCRYPTION_KEY: string;
};

type StoredOAuthState = {
  oauthReqInfo: AuthRequest;
  sessionToken: string;
  createdAt: number;
};

type MisocaTokenResponse = {
  access_token: string;
  token_type?: string;
  expires_in?: number;
  refresh_token?: string;
  scope?: string | string[];
};

const MISOCA_AUTHORIZE_URL = "https://app.misoca.jp/oauth2/authorize";
const MISOCA_TOKEN_URL = "https://app.misoca.jp/oauth2/token";
const MISOCA_API_BASE = "https://app.misoca.jp/api/v3";

function randomToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);

  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function getCookie(request: Request, name: string): string | null {
  const cookie = request.headers.get("Cookie");
  if (!cookie) return null;

  for (const part of cookie.split(";")) {
    const [key, ...rest] = part.trim().split("=");

    if (key === name) {
      return decodeURIComponent(rest.join("="));
    }
  }

  return null;
}

function sessionCookie(value: string): string {
  return [
    `__Host-MISOCA_OAUTH=${encodeURIComponent(value)}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Max-Age=600",
  ].join("; ");
}

function clearSessionCookie(): string {
  return [
    "__Host-MISOCA_OAUTH=",
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Max-Age=0",
  ].join("; ");
}

function callbackUrl(request: Request): string {
  return new URL("/callback", request.url).href;
}

function errorResponse(message: string, status = 400): Response {
  return new Response(message, {
    status,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
    },
  });
}

async function exchangeAuthorizationCode(
  env: MisocaEnv,
  code: string,
  redirectUri: string,
): Promise<MisocaTokenResponse> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    client_id: env.MISOCA_CLIENT_ID,
    client_secret: env.MISOCA_CLIENT_SECRET,
  });

  const response = await fetch(MISOCA_TOKEN_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body,
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(
      `Misoca token exchange failed (${response.status}): ${text}`,
    );
  }

  return (await response.json()) as MisocaTokenResponse;
}

export async function refreshMisocaToken(
  env: Pick<MisocaEnv, "MISOCA_CLIENT_ID" | "MISOCA_CLIENT_SECRET">,
  refreshToken: string,
): Promise<MisocaTokenResponse> {
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    client_id: env.MISOCA_CLIENT_ID,
    client_secret: env.MISOCA_CLIENT_SECRET,
  });

  const response = await fetch(MISOCA_TOKEN_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body,
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(
      `Misoca token refresh failed (${response.status}): ${text}`,
    );
  }

  return (await response.json()) as MisocaTokenResponse;
}

async function getMisocaUser(
  accessToken: string,
): Promise<Record<string, unknown>> {
  const response = await fetch(`${MISOCA_API_BASE}/user/me`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/json",
    },
  });

  if (!response.ok) {
    const text = await response.text();

    throw new Error(
      `Failed to fetch Misoca user (${response.status}): ${text}`,
    );
  }

  return (await response.json()) as Record<string, unknown>;
}

async function handleAuthorize(
  request: Request,
  env: MisocaEnv,
): Promise<Response> {
  const oauthReqInfo = await env.OAUTH_PROVIDER.parseAuthRequest(request);

  if (!oauthReqInfo.clientId) {
    return errorResponse("Invalid OAuth request.");
  }

  const stateToken = randomToken();
  const browserSession = randomToken();

  const stored: StoredOAuthState = {
    oauthReqInfo,
    sessionToken: browserSession,
    createdAt: Date.now(),
  };

  await env.OAUTH_KV.put(
    `misoca-oauth-state:${stateToken}`,
    JSON.stringify(stored),
    {
      expirationTtl: 600,
    },
  );

  const authorizeUrl = new URL(MISOCA_AUTHORIZE_URL);

  authorizeUrl.searchParams.set("response_type", "code");
  authorizeUrl.searchParams.set("client_id", env.MISOCA_CLIENT_ID);
  authorizeUrl.searchParams.set("redirect_uri", callbackUrl(request));
  authorizeUrl.searchParams.set("scope", "read");
  authorizeUrl.searchParams.set("state", stateToken);

  return new Response(null, {
    status: 302,
    headers: {
      Location: authorizeUrl.toString(),
      "Set-Cookie": sessionCookie(browserSession),
    },
  });
}

async function handleCallback(
  request: Request,
  env: MisocaEnv,
): Promise<Response> {
  const url = new URL(request.url);

  const oauthError = url.searchParams.get("error");

  if (oauthError) {
    const description =
      url.searchParams.get("error_description") ?? oauthError;

    return errorResponse(`Misoca authorization failed: ${description}`);
  }

  const code = url.searchParams.get("code");
  const stateToken = url.searchParams.get("state");

  if (!code || !stateToken) {
    return errorResponse("Missing OAuth code or state.");
  }

  const stateKey = `misoca-oauth-state:${stateToken}`;
  const rawState = await env.OAUTH_KV.get(stateKey);

  if (!rawState) {
    return errorResponse("OAuth state is invalid or expired.");
  }

  let stored: StoredOAuthState;

  try {
    stored = JSON.parse(rawState) as StoredOAuthState;
  } catch {
    await env.OAUTH_KV.delete(stateKey);
    return errorResponse("OAuth state is invalid.");
  }

  const browserSession = getCookie(request, "__Host-MISOCA_OAUTH");

  if (
    !browserSession ||
    browserSession !== stored.sessionToken
  ) {
    await env.OAUTH_KV.delete(stateKey);

    return errorResponse(
      "OAuth browser session validation failed.",
      403,
    );
  }

  // State is one-time use.
  await env.OAUTH_KV.delete(stateKey);

  let token: MisocaTokenResponse;

  try {
    token = await exchangeAuthorizationCode(
      env,
      code,
      callbackUrl(request),
    );
  } catch (error) {
    console.error(error);

    return errorResponse(
      error instanceof Error
        ? error.message
        : "Misoca token exchange failed.",
      500,
    );
  }

  if (!token.access_token) {
    return errorResponse(
      "Misoca did not return an access token.",
      500,
    );
  }

  let user: Record<string, unknown>;

  try {
    user = await getMisocaUser(token.access_token);
  } catch (error) {
    console.error(error);

    return errorResponse(
      error instanceof Error
        ? error.message
        : "Failed to read Misoca user.",
      500,
    );
  }

  const rawUserId =
    user.id ??
    user.user_id ??
    user.email ??
    user.mail_address ??
    "misoca-user";

  const rawLabel =
    user.name ??
    user.user_name ??
    user.email ??
    user.mail_address ??
    "Misoca";

  const userId = String(rawUserId);
  const userLabel = String(rawLabel);

  const expiresAt = token.expires_in
    ? Date.now() + token.expires_in * 1000
    : undefined;

  const props: MisocaProps = {
    accessToken: token.access_token,
    refreshToken: token.refresh_token,
    expiresAt,
    userId,
    userLabel,
  };

  const { redirectTo } =
    await env.OAUTH_PROVIDER.completeAuthorization({
      request: stored.oauthReqInfo,
      userId,
      metadata: {
        label: userLabel,
      },
      scope: stored.oauthReqInfo.scope,
      props,
    });

  return new Response(null, {
    status: 302,
    headers: {
      Location: redirectTo,
      "Set-Cookie": clearSessionCookie(),
    },
  });
}

export const MisocaHandler = {
  async fetch(
    request: Request,
    env: MisocaEnv,
  ): Promise<Response> {
    const url = new URL(request.url);

    try {
      if (
        url.pathname === "/authorize" &&
        request.method === "GET"
      ) {
        return await handleAuthorize(request, env);
      }

      if (
        url.pathname === "/callback" &&
        request.method === "GET"
      ) {
        return await handleCallback(request, env);
      }

      if (url.pathname === "/") {
        return new Response(
          "Misoca MCP Server is running.",
          {
            status: 200,
            headers: {
              "Content-Type": "text/plain; charset=utf-8",
            },
          },
        );
      }

      return new Response("Not found", {
        status: 404,
      });
    } catch (error) {
      console.error("Misoca OAuth error:", error);

      return errorResponse(
        error instanceof Error
          ? error.message
          : "Unexpected OAuth error.",
        500,
      );
    }
  },
};
