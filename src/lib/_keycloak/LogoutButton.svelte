<script lang="ts">
  import { getContext } from "svelte";
  import {
    OIDC_CONTEXT_CLIENT_PROMISE,
    OIDC_CONTEXT_POST_LOGOUT_REDIRECT_URI,
    logout,
  } from "./Keycloak.svelte";
  import type { OidcContextClientPromise } from "../types";

  const oidcPromise: OidcContextClientPromise = getContext(
    OIDC_CONTEXT_CLIENT_PROMISE
  );
  const post_logout_redirect_uri: string = getContext(
    OIDC_CONTEXT_POST_LOGOUT_REDIRECT_URI
  );

  let _class: string = "btn btn-primary";
  export { _class as class };
</script>

<button
  class={_class}
  on:click|preventDefault={() => logout(oidcPromise, post_logout_redirect_uri)}
>
  <slot />
</button>
