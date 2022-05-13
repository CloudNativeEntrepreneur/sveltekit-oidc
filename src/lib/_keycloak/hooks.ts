import type { Locals, OIDCResponse, UserDetailsGeneratorFn } from "../types";
import { parseCookie } from "./cookie";
import { isTokenExpired } from "./jwt";
import {
  initiateBackChannelOIDCAuth,
  initiateBackChannelOIDCLogout,
  introspectOIDCToken,
  renewOIDCToken,
} from "./auth-api";
import {
  injectCookies,
  isAuthInfoInvalid,
  parseUser,
  populateResponseHeaders,
  populateRequestLocals,
  setRequestLocalsFromNewTokens,
} from "./server-utils";
import debug from "debug";
import type { RequestEvent } from "@sveltejs/kit/types/internal";

const log = debug("sveltekit-oidc:_keycloak/hooks");

export const getUserSession = async (
  event: RequestEvent,
  issuer,
  clientId,
  clientSecret,
  refreshTokenMaxRetries
) => {
  const oidcBaseUrl = `${issuer}/protocol/openid-connect`;
  const { request } = event;
  let locals: Locals = event.locals as Locals;

  log("Get user session - locals");
  log(locals);

  try {
    if (locals?.access_token) {
      if (
        locals.user &&
        locals.userid &&
        !isTokenExpired(locals.access_token)
      ) {
        let isTokenActive = true;
        try {
          const tokenIntrospect = await introspectOIDCToken(
            locals.access_token,
            oidcBaseUrl,
            clientId,
            clientSecret,
            locals.user.preferred_username
          );
          isTokenActive = Object.keys(tokenIntrospect).includes("active")
            ? tokenIntrospect.active
            : false;
          log("token introspection ", tokenIntrospect);
          log("token active ", isTokenActive);
        } catch (e) {
          isTokenActive = false;
          console.error("Error while fetching introspect details", e);
        }
        if (isTokenActive) {
          return {
            user: { ...locals.user },
            access_token: locals.access_token,
            refresh_token: locals.refresh_token,
            id_token: locals.id_token,
            userid: locals.user.sub,
            auth_server_online: true,
          };
        }
      }

      // test connection
      try {
        const testAuthServerResponse = await fetch(
          import.meta.env.VITE_OIDC_ISSUER,
          {
            headers: {
              "Content-Type": "application/json",
            },
          }
        );
        if (!testAuthServerResponse.ok) {
          throw {
            error: await testAuthServerResponse.json(),
          };
        }
      } catch (e) {
        throw {
          error: "auth_server_conn_error",
          error_description: "Auth Server Connection Error",
        };
      }

      // get userinfo
      const res = await fetch(`${oidcBaseUrl}/userinfo`, {
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${locals.access_token}`,
        },
      });

      if (res.ok) {
        const data = await res.json();
        // log('userinfo fetched');
        locals.userid = data.sub;
        locals.user = { ...data };

        return {
          user: {
            // only include properties needed client-side —
            // exclude anything else attached to the user
            // like access tokens etc
            ...data,
          },
          access_token: locals.access_token,
          refresh_token: locals.refresh_token,
          id_token: locals.id_token,
          userid: data.sub,
          auth_server_online: true,
        };
      } else {
        try {
          const data = await res.json();
          // log(data, import.meta.env.VITE_OIDC_TOKEN_REFRESH_MAX_RETRIES);
          if (
            data?.error &&
            locals?.retries <
              import.meta.env.VITE_OIDC_TOKEN_REFRESH_MAX_RETRIES
          ) {
            log("old token expiry", isTokenExpired(locals.access_token));
            const newTokenData = await renewOIDCToken(
              locals.refresh_token,
              oidcBaseUrl,
              clientId,
              clientSecret
            );
            log("new token data:");
            log(newTokenData);
            if (newTokenData?.error) {
              throw {
                error: data?.error ? data.error : "user_info error",
                error_description: data?.error_description
                  ? data.error_description
                  : "Unable to retrieve user Info",
              };
            } else {
              locals.access_token = newTokenData.access_token;
              locals.refresh_token = newTokenData.refresh_token;
              locals.id_token = newTokenData.id_token;
              locals.retries = locals.retries + 1;
              return await getUserSession(
                event,
                issuer,
                clientId,
                clientSecret,
                refreshTokenMaxRetries
              );
            }
          }

          throw {
            error: data?.error ? data.error : "user_info error",
            error_description: data?.error_description
              ? data.error_description
              : "Unable to retrieve user Info",
          };
        } catch (e) {
          // console.error('Error while refreshing access_token; access_token is invalid', e);
          throw {
            ...e,
          };
        }
      }
    } else {
      // console.error('getSession locals.access_token ', locals.access_token);
      try {
        if (
          locals?.retries < import.meta.env.VITE_OIDC_TOKEN_REFRESH_MAX_RETRIES
        ) {
          log("old token expiry", isTokenExpired(locals.access_token));
          const newTokenData = await renewOIDCToken(
            locals.refresh_token,
            oidcBaseUrl,
            clientId,
            clientSecret
          );
          // log(newTokenData);
          if (newTokenData?.error) {
            throw {
              error: newTokenData.error,
              error_description: newTokenData.error_description,
            };
          } else {
            locals.access_token = newTokenData.access_token;
            locals.refresh_token = newTokenData.refresh_token;
            locals.id_token = newTokenData.id_token;
            locals.retries = locals.retries + 1;
            return await getUserSession(
              event,
              issuer,
              clientId,
              clientSecret,
              refreshTokenMaxRetries
            );
          }
        }
      } catch (e) {
        console.error(
          "Error while refreshing access_token; access_token is missing",
          e
        );
      }
      try {
        const testAuthServerResponse = await fetch(
          import.meta.env.VITE_OIDC_ISSUER,
          {
            headers: {
              "Content-Type": "application/json",
            },
          }
        );
        if (!testAuthServerResponse.ok) {
          throw {
            error: await testAuthServerResponse.json(),
          };
        }
      } catch (e) {
        throw {
          error: "auth_server_conn_error",
          error_description: "Auth Server Connection Error",
        };
      }
      throw {
        error: "missing_jwt",
        error_description: "access token not found or is null",
      };
    }
  } catch (err) {
    locals.access_token = "";
    locals.refresh_token = "";
    locals.id_token = "";
    locals.userid = "";
    locals.user = null;
    if (err?.error) {
      locals.authError.error = err.error;
    }
    if (err?.error_description) {
      locals.authError.error_description = err.error_description;
    }
    return {
      user: null,
      access_token: null,
      refresh_token: null,
      id_token: null,
      userid: null,
      error: locals.authError?.error ? locals.authError : null,
      auth_server_online: err.error !== "auth_server_conn_error" ? true : false,
    };
  }
};

export const userDetailsGenerator: UserDetailsGeneratorFn = async function* (
  event: RequestEvent,
  issuer,
  clientId,
  clientSecret,
  appRedirectUrl
) {
  const oidcBaseUrl = `${issuer}/protocol/openid-connect`;
  const { request } = event;

  let locals: Locals = event.locals as Locals;
  const cookies = request.headers.get("cookie")
    ? parseCookie(request.headers.get("cookie") || "")
    : null;

  const userInfo = cookies?.["userInfo"]
    ? JSON.parse(cookies?.["userInfo"])
    : {};

  locals.retries = 0;
  locals.authError = {
    error: null,
    error_description: null,
  };

  populateRequestLocals(event, "userid", userInfo, "");
  populateRequestLocals(event, "access_token", userInfo, null);
  populateRequestLocals(event, "refresh_token", userInfo, null);

  let ssr_redirect = false;
  let ssr_redirect_uri = "/";

  // Handling user logout
  if (event.url.searchParams.get("event") === "logout") {
    await initiateBackChannelOIDCLogout(
      locals.access_token,
      clientId,
      clientSecret,
      oidcBaseUrl,
      locals.refresh_token
    );
    locals.access_token = null;
    locals.refresh_token = null;
    locals.id_token = null;
    locals.authError = {
      error: "invalid_session",
      error_description: "Session is no longer active",
    };
    locals.user = null;
    ssr_redirect_uri = event.url.hostname;

    let response = new Response(null, {
      headers: {
        Location: "/",
      },
      status: 302,
    });

    try {
      response = populateResponseHeaders(event, response);
      response = injectCookies(event, response);
    } catch (e) {}
    log("returning logout response", response, request.url);
    return response;
  }

  // Parsing user object
  const userJsonParseFailed = parseUser(event, userInfo);

  // Backchannel Authorization code flow
  if (
    event.url.searchParams.get("code") &&
    (!isAuthInfoInvalid(locals) || isTokenExpired(locals.access_token))
  ) {
    const jwts: OIDCResponse = await initiateBackChannelOIDCAuth(
      event.url.searchParams.get("code"),
      clientId,
      clientSecret,
      oidcBaseUrl,
      appRedirectUrl + event.url.pathname
    );
    if (jwts.error) {
      locals.authError = {
        error: jwts.error,
        error_description: jwts.error_description,
      };
    } else {
      locals.access_token = jwts?.access_token;
      locals.refresh_token = jwts?.refresh_token;
    }
    ssr_redirect = true;
    ssr_redirect_uri = event.url.pathname;
  }

  const tokenExpired = isTokenExpired(locals.access_token);
  const beforeAccessToken = locals.access_token;

  event = { ...event, ...(yield) };

  let response = { status: 200, headers: {} };
  const afterAccessToken = locals.access_token;

  if (isAuthInfoInvalid(request.headers) || tokenExpired) {
    response = populateResponseHeaders(event, response);
  }

  if (
    isAuthInfoInvalid(userInfo) ||
    (locals?.user && userJsonParseFailed) ||
    tokenExpired ||
    beforeAccessToken !== afterAccessToken
  ) {
    // if this is the first time the user has visited this app,
    // set a cookie so that we recognise them when they return
    injectCookies(event, response);
  }
  // if (ssr_redirect) {
  //   response.status = 302;
  //   response.headers["Location"] = ssr_redirect_uri;
  // }

  return response;
};
