import type { Locals, UserDetailsGeneratorFn } from "../types";
import { parseCookie } from "./cookie";
import { isTokenExpired } from "./jwt";
import { introspectOIDCToken, renewOIDCToken } from "./auth-api";
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

export const getUserSession = async (
  event: RequestEvent,
  issuer,
  clientId,
  clientSecret,
  refreshTokenMaxRetries
) => {
  const oidcBaseUrl = `${issuer}/protocol/openid-connect`;
  const { request } = event;
  try {
    if ((event.locals as Locals)?.access_token) {
      if (
        (event.locals as Locals).user &&
        (event.locals as Locals).userid &&
        !isTokenExpired((event.locals as Locals).access_token)
      ) {
        let isTokenActive = true;
        try {
          const tokenIntrospect = await introspectOIDCToken(
            (event.locals as Locals).access_token,
            oidcBaseUrl,
            clientId,
            clientSecret,
            (event.locals as Locals).user.preferred_username
          );
          isTokenActive = Object.keys(tokenIntrospect).includes("active")
            ? tokenIntrospect.active
            : false;
          console.log("token active ", isTokenActive);
        } catch (e) {
          isTokenActive = false;
          console.error("Error while fetching introspect details", e);
        }
        if (isTokenActive) {
          return {
            user: { ...(event.locals as Locals).user },
            access_token: (event.locals as Locals).access_token,
            refresh_token: (event.locals as Locals).refresh_token,
            userid: (event.locals as Locals).user.sub,
            auth_server_online: true,
          };
        }
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
      const res = await fetch(`${oidcBaseUrl}/userinfo`, {
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${(event.locals as Locals).access_token}`,
        },
      });
      if (res.ok) {
        const data = await res.json();
        // console.log('userinfo fetched');
        (event.locals as Locals).userid = data.sub;
        (event.locals as Locals).user = { ...data };
        return {
          user: {
            // only include properties needed client-side —
            // exclude anything else attached to the user
            // like access tokens etc
            ...data,
          },
          access_token: (event.locals as Locals).access_token,
          refresh_token: (event.locals as Locals).refresh_token,
          userid: data.sub,
          auth_server_online: true,
        };
      } else {
        try {
          const data = await res.json();
          // console.log(data, import.meta.env.VITE_OIDC_TOKEN_REFRESH_MAX_RETRIES);
          if (
            data?.error &&
            (event.locals as Locals)?.retries <
              import.meta.env.VITE_OIDC_TOKEN_REFRESH_MAX_RETRIES
          ) {
            console.log(
              "old token expiry",
              isTokenExpired((event.locals as Locals).access_token)
            );
            const newTokenData = await renewOIDCToken(
              (event.locals as Locals).refresh_token,
              oidcBaseUrl,
              clientId,
              clientSecret
            );
            // console.log(newTokenData);
            if (newTokenData?.error) {
              throw {
                error: data?.error ? data.error : "user_info error",
                error_description: data?.error_description
                  ? data.error_description
                  : "Unable to retrieve user Info",
              };
            } else {
              (event.locals as Locals).access_token = newTokenData.access_token;
              (event.locals as Locals).retries = (event.locals as Locals).retries + 1;
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
      // console.error('getSession (event.locals as Locals).access_token ', (event.locals as Locals).access_token);
      try {
        if (
          (event.locals as Locals)?.retries <
          import.meta.env.VITE_OIDC_TOKEN_REFRESH_MAX_RETRIES
        ) {
          console.log(
            "old token expiry",
            isTokenExpired((event.locals as Locals).access_token)
          );
          const newTokenData = await renewOIDCToken(
            (event.locals as Locals).refresh_token,
            oidcBaseUrl,
            clientId,
            clientSecret
          );
          // console.log(newTokenData);
          if (newTokenData?.error) {
            throw {
              error: newTokenData.error,
              error_description: newTokenData.error_description,
            };
          } else {
            (event.locals as Locals).access_token = newTokenData.access_token;
            (event.locals as Locals).retries = (event.locals as Locals).retries + 1;
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
    (event.locals as Locals).access_token = "";
    (event.locals as Locals).refresh_token = "";
    (event.locals as Locals).userid = "";
    (event.locals as Locals).user = null;
    if (err?.error) {
      (event.locals as Locals).authError.error = err.error;
    }
    if (err?.error_description) {
      (event.locals as Locals).authError.error_description = err.error_description;
    }
    return {
      user: null,
      access_token: null,
      refresh_token: null,
      userid: null,
      error: (event.locals as Locals).authError?.error ? (event.locals as Locals).authError : null,
      auth_server_online: err.error !== "auth_server_conn_error" ? true : false,
    };
  }
};

export const userDetailsGenerator: UserDetailsGeneratorFn = async function* (
  event: RequestEvent
) {
  const { request } = event;
  const cookies = request.headers.get("cookie")
    ? parseCookie(request.headers.get("cookie") || "")
    : null;

  const userInfo = cookies?.["userInfo"]
    ? JSON.parse(cookies?.["userInfo"])
    : {};

  (event.locals as Locals).retries = 0;
  (event.locals as Locals).authError = {
    error: null,
    errorDescription: null,
  };

  populateRequestLocals(event, "userid", userInfo, "");
  populateRequestLocals(event, "access_token", userInfo, null);
  populateRequestLocals(event, "refresh_token", userInfo, null);

  let ssr_redirect = false;
  let ssr_redirect_uri = "/";

  // Handling user logout
  // if (request.query.get("event") === "logout") {
  //   await initiateBackChannelOIDCLogout(
  //     (event.locals as Locals).access_token,
  //     clientId,
  //     clientSecret,
  //     oidcBaseUrl,
  //     (event.locals as Locals).refresh_token
  //   );
  //   (event.locals as Locals).access_token = null;
  //   (event.locals as Locals).refresh_token = null;
  //   (event.locals as Locals).authError = {
  //     error: "invalid_session",
  //     error_description: "Session is no longer active",
  //   };
  //   (event.locals as Locals).user = null;
  //   ssr_redirect_uri = request.path;
  //   let response: ServerResponse = {
  //     status: 302,
  //     headers: {
  //       Location: ssr_redirect_uri,
  //     },
  //   };
  //   try {
  //     response = populateResponseHeaders(request, response);
  //     response = injectCookies(request, response);
  //   } catch (e) {}
  //   return response;
  // }

  // Parsing user object
  const userJsonParseFailed = parseUser(event, userInfo);

  // Backchannel Authorization code flow
  // if (
  //   request.query.get("code") &&
  //   (!isAuthInfoInvalid((event.locals as Locals)) ||
  //     isTokenExpired((event.locals as Locals).access_token))
  // ) {
  //   const jwts: OIDCResponse = await initiateBackChannelOIDCAuth(
  //     request.query.get("code"),
  //     clientId,
  //     clientSecret,
  //     oidcBaseUrl,
  //     appRedirectUrl + request.path
  //   );
  //   if (jwts.error) {
  //     (event.locals as Locals).authError = {
  //       error: jwts.error,
  //       error_description: jwts.error_description,
  //     };
  //   } else {
  //     (event.locals as Locals).access_token = jwts?.access_token;
  //     (event.locals as Locals).refresh_token = jwts?.refresh_token;
  //   }
  //   ssr_redirect = true;
  //   ssr_redirect_uri = request.path;
  // }

  const tokenExpired = isTokenExpired((event.locals as Locals).access_token);
  const beforeAccessToken = (event.locals as Locals).access_token;

  event = { ...event, ...(yield) };

  let response = { status: 200, headers: {} };
  const afterAccessToken = (event.locals as Locals).access_token;

  if (isAuthInfoInvalid(request.headers) || tokenExpired) {
    response = populateResponseHeaders(event, response);
  }

  if (
    isAuthInfoInvalid(userInfo) ||
    ((event.locals as Locals)?.user && userJsonParseFailed) ||
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
