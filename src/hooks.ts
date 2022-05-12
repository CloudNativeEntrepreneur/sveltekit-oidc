import type { Handle, GetSession } from "@sveltejs/kit";
import type { RequestEvent } from "@sveltejs/kit/types/internal";
import type { Locals } from "$lib/types";
import {
  userDetailsGenerator,
  getUserSession,
  getServerOnlyEnvVar,
} from "$lib";
import { config } from "./config";
import debug from "debug";

const log = debug("sveltekit-oidc:hooks");

const issuer = config.oidc.issuer;
const clientId = config.oidc.clientId;
const clientSecret =
  getServerOnlyEnvVar(process, "OIDC_CLIENT_SECRET") ||
  config.oidc.clientSecret;
const refreshTokenMaxRetries = config.oidc.refreshTokenMaxRetries;

// https://kit.svelte.dev/docs#hooks-handle
export const handle: Handle = async ({ event, resolve }) => {
  log("handle", event.request.url);

  // Initialization part
  const userGen = userDetailsGenerator(event);
  const { value, done } = await userGen.next();
  if (done) {
    const response = value;
    return response;
  }

  // Set Cookie attributes
  (event.locals as Locals).cookieAttributes = "Path=/; HttpOnly;";

  // Your code here -----------
  log("FIX METHOD");
  // if (event.request.query.has("_method")) {
  //   event.request.method = request.query.get("_method").toUpperCase();
  // }
  // Handle resolve
  const response = await resolve(event);

  if (response?.status === 404) {
    return response;
  }

  const body = await response.text();

  const authResponse = (await userGen.next(event)).value;
  const { Location } = authResponse.headers;

  // SSR Redirection
  if (authResponse.status === 302 && Location) {
    const redirectResponse = {
      ...response,
      status: authResponse.status,
      headers: {
        "content-type": response.headers.get("content-type"),
        etag: response.headers.get("etag"),
        "permissions-policy": response.headers.get("permissions-policy"),
        Location,
      },
    };

    return new Response(body, redirectResponse);
  }

  if (authResponse?.headers) {
    let authedResponseBase;

    if (authResponse?.headers?.userid) {
      authedResponseBase = {
        status: response.status,
        statusText: response.statusText,
        headers: {
          user: authResponse.headers.user,
          userid: authResponse.headers.userid,
          accesstoken: authResponse.headers.accesstoken,
          refreshtoken: authResponse.headers.refreshtoken,
          "set-cookie": authResponse.headers["set-cookie"],
          "content-type": response.headers.get("content-type"),
          etag: response.headers.get("etag"),
          "permissions-policy": response.headers.get("permissions-policy"),
        },
      };
    } else if (authResponse.headers["set-cookie"]) {
      authedResponseBase = {
        status: response.status,
        statusText: response.statusText,
        headers: {
          "set-cookie": authResponse.headers["set-cookie"],
          "content-type": response.headers.get("content-type"),
          etag: response.headers.get("etag"),
          "permissions-policy": response.headers.get("permissions-policy"),
        },
      };
    }
    return new Response(body, authedResponseBase);
  }

  return new Response(body, response);
};

/** @type {import('@sveltejs/kit').GetSession} */
export const getSession: GetSession = async (event: RequestEvent<Locals>) => {
  log("getting user session...");

  const userSession = await getUserSession(
    event,
    issuer,
    clientId,
    clientSecret,
    refreshTokenMaxRetries
  );

  return userSession;
};
