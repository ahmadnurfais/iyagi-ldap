import { request } from "undici";

export interface LldapClientOptions {
  baseUrl: string;
  username: string;
  password: string;
}

interface AuthState {
  token: string;
  expiresAt: number;
}

/**
 * Minimal service-account GraphQL client used by the interceptor to fetch
 * pre/post images of entities. Uses the read-only audit-interceptor account.
 * Access tokens from /auth/simple/login are short-lived; refresh on demand.
 */
export class LldapClient {
  private auth: AuthState | null = null;

  constructor(private readonly opts: LldapClientOptions) {}

  private async login(): Promise<void> {
    const res = await request(`${this.opts.baseUrl}/auth/simple/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: this.opts.username, password: this.opts.password }),
    });
    if (res.statusCode >= 400) {
      const body = await res.body.text();
      throw new Error(`lldap login failed: ${res.statusCode} ${body}`);
    }
    const body = (await res.body.json()) as { token?: string };
    if (!body.token) throw new Error("lldap login returned no token");
    this.auth = { token: body.token, expiresAt: Date.now() + 55 * 60 * 1000 };
  }

  private async token(): Promise<string> {
    if (!this.auth || Date.now() >= this.auth.expiresAt) {
      await this.login();
    }
    return this.auth!.token;
  }

  async graphql<T = unknown>(query: string, variables: Record<string, unknown> = {}): Promise<T> {
    const token = await this.token();
    const res = await request(`${this.opts.baseUrl}/api/graphql`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ query, variables }),
    });
    const text = await res.body.text();
    if (res.statusCode === 401 || res.statusCode === 403) {
      this.auth = null;
      const token2 = await this.token();
      const retry = await request(`${this.opts.baseUrl}/api/graphql`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${token2}`,
        },
        body: JSON.stringify({ query, variables }),
      });
      const retryText = await retry.body.text();
      if (retry.statusCode >= 400) {
        throw new Error(`lldap graphql failed: ${retry.statusCode} ${retryText}`);
      }
      return JSON.parse(retryText) as T;
    }
    if (res.statusCode >= 400) {
      throw new Error(`lldap graphql failed: ${res.statusCode} ${text}`);
    }
    return JSON.parse(text) as T;
  }

  async fetchUser(userId: string): Promise<Record<string, unknown> | null> {
    const query = `query($id:String!){user(userId:$id){id email displayName firstName lastName creationDate uuid groups{id displayName}}}`;
    try {
      const res = await this.graphql<{ data?: { user?: Record<string, unknown> | null } }>(query, { id: userId });
      return res.data?.user ?? null;
    } catch {
      return null;
    }
  }

  async fetchGroup(groupIdOrName: string): Promise<Record<string, unknown> | null> {
    const numeric = /^[0-9]+$/.test(groupIdOrName);
    if (numeric) {
      const query = `query($id:Int!){group(groupId:$id){id displayName creationDate uuid users{id}}}`;
      try {
        const res = await this.graphql<{ data?: { group?: Record<string, unknown> | null } }>(query, { id: Number(groupIdOrName) });
        return res.data?.group ?? null;
      } catch {
        return null;
      }
    }
    const q = `query{groups{id displayName creationDate uuid users{id}}}`;
    try {
      const res = await this.graphql<{ data?: { groups?: Array<Record<string, unknown>> } }>(q, {});
      const list = res.data?.groups ?? [];
      return list.find((g) => g.displayName === groupIdOrName) ?? null;
    } catch {
      return null;
    }
  }
}
