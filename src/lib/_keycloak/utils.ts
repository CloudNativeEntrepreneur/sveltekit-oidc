import type { LoadOutput } from "@sveltejs/kit";
import type {
  Locals,
  OIDCFailureResponse,
  OIDCResponse,
  UserDetailsGeneratorFn,
  GetUserSessionFn,
} from "../types";
import { parseCookie } from "./cookie";
import type { ServerRequest, ServerResponse } from "@sveltejs/kit/types/hooks";


export const clientId = `${import.meta.env.VITE_OIDC_CLIENT_ID}`;
let appRedirectUrl = import.meta.env.VITE_OIDC_REDIRECT_URI;
