<script context="module" lang="ts">
  import { initiateFrontChannelOIDCAuth } from "./auth-api";
  import type {
    OidcContextClientFn,
    OidcContextClientPromise,
    UserSession,
  } from "../types";
  import debug from "debug";
  import { get, writable } from "svelte/store";

  const log = debug("sveltekit-oidc:lib/_keycloak/Keycloak.svelte");

  log("KEYCLOAK AUTH");

  export const OIDC_CONTEXT_CLIENT_PROMISE = {};
  export const OIDC_CONTEXT_REDIRECT_URI: string = "";
  export const OIDC_CONTEXT_POST_LOGOUT_REDIRECT_URI: string = "";

  /**
   * Stores
   */
  export const isLoading = writable(true);
  export const isAuthenticated = writable(false);
  export const accessToken = writable("");
  export const idToken = writable("");
  export const refreshToken = writable("");
  export const userInfo = writable({});
  export const authError = writable(null);

  const AuthStore = {
    isLoading,
    isAuthenticated,
    accessToken,
    idToken,
    refreshToken,
    userInfo,
    authError,
  };

  // const onReceivedNewTokens = (tokens: {
  //   accessToken: string;
  //   idToken: string;
  //   refreshToken: string;
  // }) => {
  //   const user = getTokenData(tokens.idToken);
  //   delete user.aud;
  //   delete user.exp;
  //   delete user.iat;
  //   delete user.iss;
  //   delete user.sub;
  //   delete user.typ;
  //   if (user?.username) {
  //     user.username = decodeURI(user.username);
  //   }

  //   AuthStore.isAuthenticated.set(true);
  //   AuthStore.accessToken.set(tokens.accessToken);
  //   AuthStore.refreshToken.set(tokens.refreshToken);
  //   AuthStore.idToken.set(tokens.idToken);
  //   AuthStore.userInfo.set({
  //     ...user,
  //   });

  //   session.set({
  //     userid: user.userid,
  //     accessToken: tokens.accessToken,
  //     refreshToken: tokens.refreshToken,
  //     user,
  //     authServerOnline: true,
  //   });

  //   log("session updated");

  //   return user;
  // };

  const clearAuthStoreInfo = () => {
    AuthStore.isAuthenticated.set(false);
    AuthStore.accessToken.set(null);
    AuthStore.refreshToken.set(null);
    AuthStore.idToken.set(null);
    AuthStore.userInfo.set(null);
  };

  // const handleLoggedIn = (tokens: any) => {
  //   const user = onReceivedNewTokens(tokens);
  //   localStorage.removeItem("user_logout");
  //   localStorage.setItem("user_login", JSON.stringify(user));
  // };

  const checkAuthServerIsOnline = async (issuer) => {
    const testAuthServerResponse = await fetch(issuer, {
      headers: {
        "Content-Type": "application/json",
      },
    });
    if (testAuthServerResponse.ok) {
      handleAuthServerOnline();
    } else {
      throw {
        error: await testAuthServerResponse.json(),
      };
    }
  };

  const handleAuthServerOnline = () => {
    session.set({
      ...session,
      authServerOnline: true,
    });
  };

  const handleAuthServerOffline = (error) => {
    const errorType = "auth_server_conn_error";
    const errorDescription = `Auth Server Connection Error: ${error.toString()}`;
    console.error(errorDescription);
    AuthStore.isLoading.set(false);
    AuthStore.authError.set({
      error: errorType,
      errorDescription,
    });
    session.set({
      ...session,
      authServerOnline: false,
    });
  };

  const setAuthStoreInfoFromSession = (currentSession) => {
    log("SESSION", currentSession);
    AuthStore.isAuthenticated.set(true);
    AuthStore.accessToken.set(currentSession.accessToken);
    AuthStore.refreshToken.set(currentSession.refreshToken);
    AuthStore.idToken.set(currentSession.idToken);
    AuthStore.authError.set(null);
  };

  export async function login(oidcPromise: OidcContextClientPromise) {
    debugger;
    const oidcContextClientFn = await oidcPromise;
    const { session, issuer, page, client_id, redirect } =
      oidcContextClientFn();

    try {
      // check server is online if it was marked as offline in the session
      // such as if the server side couldn't reach the auth server
      if (session?.authServerOnline === false) {
        await checkAuthServerIsOnline(issuer);
      }
    } catch (error) {
      return handleAuthServerOffline(error);
    }

    AuthStore.isLoading.set(true);

    const errorsToReinitiateLogin = [
      "missing_jwt",
      "invalid_grant",
      "invalid_token",
      "token_refresh_error",
    ];

    const hasErrorThatShouldResultInLoggingInAgain = session?.error?.error
      ? errorsToReinitiateLogin.includes(session.error.error)
      : false;

    if (
      !session?.user &&
      (!session?.error || hasErrorThatShouldResultInLoggingInAgain)
    ) {
      clearAuthStoreInfo();
      window.location.assign(redirect);
    } else if (session?.error) {
      log("There is an error in the session", session?.error);
      clearAuthStoreInfo();
      AuthStore.authError.set(session.error);
      AuthStore.isLoading.set(false);
      window.location.assign(redirect);
    } else {
      AuthStore.isLoading.set(false);
      setAuthStoreInfoFromSession(session);
    }
  }

  export async function logout(
    oidcPromise: OidcContextClientPromise,
    post_logout_redirect_uri: string
  ) {
    debugger;
    const oidc_func = await oidcPromise;
    const { issuer, client_id } = oidc_func();
    const logout_endpoint = `${issuer}/protocol/openid-connect/logout`;
    const logout_uri = `${issuer}/protocol/openid-connect/logout?id_token_hint=${get(
      AuthStore.idToken
    )}&post_logout_redirect_uri=${encodeURIComponent(
      post_logout_redirect_uri + "?event=logout"
    )}`;

    const res = await fetch(logout_endpoint, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${get(AuthStore.accessToken)}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: `client_id=${client_id}&refresh_token=${get(
        AuthStore.refreshToken
      )}`,
    });
    window.localStorage.setItem("user_logout", "true");
    if (res.ok) {
      window.location.assign(logout_uri);
    } else {
      window.location.assign(logout_uri);
    }
  }
</script>

<script lang="ts">
  import { setContext } from "svelte";
  import { onMount, onDestroy } from "svelte";
  import { browser } from "$app/env";

  import { page, session } from "$app/stores";
  import { getTokenData } from "./jwt";

  // props.
  export let issuer: string;
  export let client_id: string;
  export let redirect_uri: string;
  export let post_logout_redirect_uri: string;
  export let scope: string;
  export let refresh_token_endpoint: string;
  export let refresh_page_on_session_timeout: boolean = false;

  const oidcBaseUrl = `${issuer}/protocol/openid-connect`;

  const oidc_func: OidcContextClientFn = (
    request_path?: string,
    request_params?: Record<string, string>
  ) => {
    return {
      redirect: initiateFrontChannelOIDCAuth(
        browser,
        oidcBaseUrl,
        client_id,
        scope,
        redirect_uri,
        request_path,
        request_params
      ).redirect,
      session: $session,
      issuer,
      page: $page,
      client_id,
    };
  };
  const oidc_auth_promise: OidcContextClientPromise =
    Promise.resolve(oidc_func);
  setContext(OIDC_CONTEXT_CLIENT_PROMISE, oidc_auth_promise);
  setContext(OIDC_CONTEXT_REDIRECT_URI, redirect_uri);
  setContext(OIDC_CONTEXT_POST_LOGOUT_REDIRECT_URI, post_logout_redirect_uri);

  let tokenTimeoutObj = null;
  export async function silentRefresh(oldRefreshToken: string) {
    try {
      const reqBody = `refresh_token=${oldRefreshToken}`;
      const res = await fetch(refresh_token_endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: reqBody,
      });
      if (res.ok) {
        const resData = await res.json();
        if (!resData.error) {
          const { access_token, refresh_token, id_token } = resData;
          AuthStore.accessToken.set(access_token);
          AuthStore.refreshToken.set(refresh_token);
          AuthStore.idToken.set(id_token);
          const jwtData = JSON.parse(
            atob(access_token.split(".")[1]).toString()
          );
          const tokenSkew = 10; // 10 seconds before actual token expiry
          const skewedTimeoutDuration =
            jwtData.exp * 1000 - tokenSkew * 1000 - new Date().getTime();
          const timeoutDuration =
            skewedTimeoutDuration > 0
              ? skewedTimeoutDuration
              : skewedTimeoutDuration + tokenSkew * 1000;
          if (tokenTimeoutObj) {
            clearTimeout(tokenTimeoutObj);
          }
          if (timeoutDuration > 0) {
            tokenTimeoutObj = setTimeout(async () => {
              await silentRefresh(refresh_token);
            }, timeoutDuration);
          } else {
            throw {
              error: "invalid_grant",
              error_description: "Session not active",
            };
          }
        } else {
          throw {
            error: resData.error,
            error_description: resData.error_description,
          };
        }
      } else {
        throw {
          error: "token_refresh_error",
          error_description: "Unable to Refresh token",
        };
      }
    } catch (e) {
      if (tokenTimeoutObj) {
        clearTimeout(tokenTimeoutObj);
      }
      AuthStore.accessToken.set(null);
      AuthStore.refreshToken.set(null);
      AuthStore.isAuthenticated.set(false);
      AuthStore.authError.set({
        error: e?.error,
        error_description: e?.error_description,
      });
      if (refresh_page_on_session_timeout) {
        window.location.assign($page.url.pathname);
      }
    }
  }
  const syncLogout = (event: StorageEvent) => {
    if (browser) {
      if (event.key === "user_logout") {
        try {
          if (JSON.parse(window.localStorage.getItem("user_logout"))) {
            window.localStorage.setItem("user_login", null);

            AuthStore.accessToken.set(null);
            AuthStore.refreshToken.set(null);
            AuthStore.isAuthenticated.set(false);
            AuthStore.authError.set({
              error: "invalid_grant",
              error_description: "Session is not active",
            });
            if (refresh_page_on_session_timeout) {
              window.location.assign($page.url.pathname);
            }
          }
        } catch (e) {}
      }
    }
  };

  const syncLogin = (event: StorageEvent) => {
    if (browser) {
      if (event.key === "user_login") {
        try {
          window.localStorage.setItem("user_logout", "false");
          const userInfo = JSON.parse(
            window.localStorage.getItem("user_login")
          );
          if (
            userInfo &&
            (!($session as UserSession).user ||
              ($session as UserSession).user?.preferred_username !==
                userInfo?.preferred_username)
          ) {
            const answer = confirm(
              `Welcome ${userInfo?.preferred_username || "user"}. Refresh page!`
            );
            if (answer) {
              window.location.assign($page.url.pathname);
            }
          }
        } catch (e) {}
      }
    }
  };

  async function handleMount() {
    log("Keycloak:handleMount");
    try {
      window.addEventListener("storage", syncLogout);
      window.addEventListener("storage", syncLogin);
    } catch (e) {}

    try {
      if (($session as UserSession)?.auth_server_online === false) {
        log("Keycloak:handleMount - testing server");
        const testAuthServerResponse = await fetch(issuer, {
          headers: {
            "Content-Type": "application/json",
          },
        });
        if (!testAuthServerResponse.ok) {
          throw {
            error: await testAuthServerResponse.json(),
          };
        }
      } else {
        AuthStore.isLoading.set(false);
        if (!($session as UserSession).user) {
          AuthStore.isAuthenticated.set(false);
          AuthStore.accessToken.set(null);
          AuthStore.refreshToken.set(null);
          AuthStore.idToken.set(null);
          if (window.location.toString().includes("event=logout")) {
            window.location.assign($page.url.pathname);
          }
        } else {
          AuthStore.isAuthenticated.set(true);
          AuthStore.accessToken.set(($session as UserSession).access_token);
          AuthStore.refreshToken.set(($session as UserSession).refresh_token);
          AuthStore.refreshToken.set(($session as UserSession).id_token);
          const jwtData = JSON.parse(
            atob(
              ($session as UserSession).access_token.split(".")[1]
            ).toString()
          );
          const tokenSkew = 10; // 10 seconds before actual token expiry
          const skewedTimeoutDuration =
            jwtData.exp * 1000 - tokenSkew * 1000 - new Date().getTime();
          const timeoutDuration =
            skewedTimeoutDuration > 0
              ? skewedTimeoutDuration
              : skewedTimeoutDuration + tokenSkew * 1000;
          tokenTimeoutObj = setTimeout(async () => {
            await silentRefresh(($session as UserSession).refresh_token);
          }, timeoutDuration);
          AuthStore.authError.set(null);
          if (window.location.toString().includes("code=")) {
            window.location.assign($page.url.pathname);
          }

          try {
            window.localStorage.setItem(
              "user_login",
              JSON.stringify(($session as UserSession).user)
            );
          } catch (e) {}
        }
      }
    } catch (e) {
      console.error(e);
      AuthStore.isLoading.set(false);
      AuthStore.isAuthenticated.set(false);
      AuthStore.accessToken.set(null);
      AuthStore.refreshToken.set(null);
      AuthStore.authError.set({
        error: "auth_server_conn_error",
        error_description: "Auth Server Connection Error",
      });
      if (window.location.toString().includes("event=logout")) {
        window.location.assign($page.url.pathname);
      }
    }
  }
  onMount(handleMount);

  onDestroy(() => {
    if (tokenTimeoutObj) {
      clearTimeout(tokenTimeoutObj);
    }
    try {
      window.removeEventListener("storage", syncLogout);
      window.removeEventListener("storage", syncLogin);
    } catch (e) {}
  });
</script>

<slot />
