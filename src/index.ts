import OAuthProvider from "@cloudflare/workers-oauth-provider";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { McpAgent } from "agents/mcp";
import { z } from "zod";

import {
  MisocaHandler,
  type MisocaProps,
  refreshMisocaToken,
} from "./misoca-auth";

const MISOCA_API_BASE = "https://app.misoca.jp/api/v3";

type McpEnv = Env & {
  MISOCA_CLIENT_ID: string;
  MISOCA_CLIENT_SECRET: string;
};

export class MyMCP extends McpAgent<
  McpEnv,
  Record<string, never>,
  MisocaProps
> {
  server = new McpServer({
    name: "Misoca MCP Server",
    version: "1.0.0",
  });

  private async getAccessToken(): Promise<string> {
    const now = Date.now();

    if (
      this.props.accessToken &&
      (!this.props.expiresAt ||
        now < this.props.expiresAt - 60_000)
    ) {
      return this.props.accessToken;
    }

    if (!this.props.refreshToken) {
      throw new Error(
        "Misoca access token expired and no refresh token is available. Reconnect Misoca.",
      );
    }

    const refreshed = await refreshMisocaToken(
      this.env,
      this.props.refreshToken,
    );

    if (!refreshed.access_token) {
      throw new Error(
        "Misoca token refresh did not return an access token.",
      );
    }

    /*
     * Use the refreshed token for this MCP object instance.
     * If Misoca rotates the refresh token, keep the new one too.
     */
    this.props.accessToken = refreshed.access_token;

    if (refreshed.refresh_token) {
      this.props.refreshToken = refreshed.refresh_token;
    }

    if (refreshed.expires_in) {
      this.props.expiresAt =
        Date.now() + refreshed.expires_in * 1000;
    }

    return this.props.accessToken;
  }

  private async misocaGet(
    path: string,
  ): Promise<unknown> {
    const accessToken = await this.getAccessToken();

    const response = await fetch(
      `${MISOCA_API_BASE}${path}`,
      {
        method: "GET",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: "application/json",
        },
      },
    );

    if (!response.ok) {
      const body = await response.text();

      throw new Error(
        `Misoca API error (${response.status}): ${body}`,
      );
    }

    return await response.json();
  }

  async init() {
    this.server.tool(
      "list_invoices",
      "Misocaの請求書一覧を取得します。",
      {
        page: z.number().int().positive().optional(),
      },
      async ({ page }) => {
        try {
          const params = new URLSearchParams();

          if (page !== undefined) {
            params.set("page", String(page));
          }

          const query = params.toString();

          const data = await this.misocaGet(
            `/invoices${query ? `?${query}` : ""}`,
          );

          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(data, null, 2),
              },
            ],
          };
        } catch (error) {
          return {
            isError: true,
            content: [
              {
                type: "text",
                text:
                  error instanceof Error
                    ? error.message
                    : "Failed to get Misoca invoices.",
              },
            ],
          };
        }
      },
    );

    this.server.tool(
      "get_invoice",
      "Misocaの請求書IDを指定して詳細を取得します。支払状況など請求書の詳細確認に使用します。",
      {
        invoiceId: z.union([
          z.string().min(1),
          z.number().int().positive(),
        ]),
      },
      async ({ invoiceId }) => {
        try {
          const id = encodeURIComponent(
            String(invoiceId),
          );

          const data = await this.misocaGet(
            `/invoice/${id}`,
          );

          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(data, null, 2),
              },
            ],
          };
        } catch (error) {
          return {
            isError: true,
            content: [
              {
                type: "text",
                text:
                  error instanceof Error
                    ? error.message
                    : "Failed to get Misoca invoice.",
              },
            ],
          };
        }
      },
    );
  }
}

export default new OAuthProvider({
  apiRoute: "/mcp",
  apiHandler: MyMCP.serve("/mcp"),
  defaultHandler: MisocaHandler as any,
  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/token",
  clientRegistrationEndpoint: "/register",
});
