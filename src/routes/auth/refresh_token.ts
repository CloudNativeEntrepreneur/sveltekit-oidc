import { getServerOnlyEnvVar, parseCookie, renewOIDCToken } from "$lib";

import type { RequestHandler } from "@sveltejs/kit";
import type { RequestEvent } from "@sveltejs/kit/types/private";

import { config } from "../../config";
import debug from "debug";

const log = debug("sveltekit-oidc:/auth/refresh_token");

const oidcBaseUrl = `${config.oidc.issuer}/protocol/openid-connect`;

const clientSecret =
  getServerOnlyEnvVar(process, "OIDC_CLIENT_SECRET") ||
  config.oidc.clientSecret;
/**
 * @type {import('@sveltejs/kit').RequestHandler}
 */
export const post: RequestHandler = async (event: RequestEvent) => {
  const { request } = event;
  const body: any = await request.json();
  const clientId = body.client_id;
  const refreshToken = body.refresh_token;

  log("refreshing token", clientId, refreshToken);
  const data = await renewOIDCToken(
    refreshToken,
    oidcBaseUrl,
    clientId,
    clientSecret
  );

  const response = {
    body: {
      ...data,
    },
  };

  return response;
};
