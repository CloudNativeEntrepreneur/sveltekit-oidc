import jwtDecode from "jwt-decode";
import type { Locals } from "$lib/types";
import type { RequestEvent } from "@sveltejs/kit/types/internal";
import debug from "debug";

const log = debug("sveltekit-oidc:server-utils");

export const injectCookies = (event: RequestEvent, response) => {
  let responseCookies = {};
  let serialized_user = null;

  let locals: Locals = event.locals as Locals;

  try {
    serialized_user = JSON.stringify(locals.user);
  } catch {
    locals.user = null;
  }
  responseCookies = {
    userid: `${locals.userid}`,
    user: `${serialized_user}`,
  };
  responseCookies["refresh_token"] = `${locals.refresh_token}`;
  let cookieAtrributes = "Path=/; HttpOnly; SameSite=Lax;";
  if (locals?.cookieAttributes) {
    cookieAtrributes = locals.cookieAttributes;
  }
  response.headers["set-cookie"] = `userInfo=${JSON.stringify(
    responseCookies
  )}; ${cookieAtrributes}`;
  return response;
};

export const isAuthInfoInvalid = (obj) => {
  const isAuthInvalid =
    !obj?.userid || !obj?.accessToken || !obj?.refreshToken || !obj?.user;
  return isAuthInvalid;
};

export const parseUser = (event: RequestEvent, userInfo) => {
  const { request } = event;
  let locals: Locals = event.locals as Locals;

  let userJsonParseFailed = false;
  try {
    if (request.headers?.get("user")) {
      locals.user = JSON.parse(request.headers.get("user"));
    } else {
      if (
        userInfo?.user &&
        userInfo?.user !== "null" &&
        userInfo?.user !== "undefined"
      ) {
        locals.user = JSON.parse(userInfo.user);
        if (!locals.user) {
          userJsonParseFailed = true;
        }
      } else {
        throw {
          error: "invalid_user_object",
        };
      }
    }
  } catch {
    userJsonParseFailed = true;
    locals.user = null;
  }
  return userJsonParseFailed;
};

export const populateRequestLocals = (
  event: RequestEvent,
  keyName: string,
  userInfo,
  defaultValue
) => {
  const { request } = event;
  let locals: Locals = event.locals as Locals;

  // log(request, locals)

  if (request?.headers.get(keyName)) {
    event.locals[keyName] = request.headers.get(keyName);
  } else {
    if (
      userInfo[keyName] &&
      userInfo[keyName] !== "null" &&
      userInfo[keyName] !== "undefined"
    ) {
      locals[keyName] = userInfo[keyName];
    } else {
      locals[keyName] = defaultValue;
    }
  }
  return request;
};

export const populateResponseHeaders = (event: RequestEvent, response) => {
  let locals: Locals = event.locals as Locals;
  if (locals.user) {
    response.headers["user"] = `${JSON.stringify(locals.user)}`;
  }

  if (locals.userid) {
    response.headers["userid"] = `${locals.userid}`;
  }

  if (locals.access_token) {
    response.headers["access_token"] = `${locals.access_token}`;
  }
  if (locals.refresh_token) {
    response.headers["refresh_token"] = `${locals.refresh_token}`;
  }
  return response;
};

export const setRequestLocalsFromNewTokens = (
  event: RequestEvent,
  tokenSet: { accessToken: string; idToken: string; refreshToken: string }
) => {
  const parsedUserInfo: any = jwtDecode(tokenSet.idToken);
  delete parsedUserInfo.aud;
  delete parsedUserInfo.exp;
  delete parsedUserInfo.iat;
  delete parsedUserInfo.iss;
  delete parsedUserInfo.sub;
  delete parsedUserInfo.typ;

  // Cookie is set based on locals value in next step
  (event.locals as Locals).userid = parsedUserInfo.address;
  (event.locals as Locals).user = parsedUserInfo;
  (event.locals as Locals).access_token = tokenSet.accessToken;
  (event.locals as Locals).refresh_token = tokenSet.refreshToken;
  (event.locals as Locals).id_token = tokenSet.idToken;
};
