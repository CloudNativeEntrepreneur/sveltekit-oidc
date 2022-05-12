import type { MaybePromise } from "@sveltejs/kit/types/helper";
import type { RequestEvent } from "@sveltejs/kit/types/hooks";

export type AuthError = {
  error: string;
  errorDescription: string;
};
export interface Locals {
  userid: string;
  access_token: string;
  refresh_token: string;
  authError?: AuthError;
  user?: any;
  retries?: number;
  cookieAttributes?: string;
}

export type OidcContextClientFn = (
  request_path?: string,
  request_params?: Record<string, string>
) => {
  redirect: string;
  session: any;
  issuer: string;
  page: Page;
  client_id: string;
};

export type OidcContextClientPromise = Promise<OidcContextClientFn>;

export interface OIDCSuccessResponse {
  access_token: string;
  id_token: string;
  refresh_token: string;
}

export interface OIDCFailureResponse extends AuthError {}

export type OIDCResponse = OIDCSuccessResponse & OIDCFailureResponse;

export interface UserDetailsGeneratorFn {
  (event: RequestEvent<Locals>): AsyncGenerator<any, any, RequestEvent<Locals>>;
}
export interface UserSession {
  user: any;
  access_token: string;
  refresh_token: string;
  userid: string;
  error?: AuthError | undefined;
  auth_server_online: boolean;
}
export interface GetUserSessionFn {
  (request: ServerRequest<Locals>, clientSecret: string): Promise<UserSession>;
}
