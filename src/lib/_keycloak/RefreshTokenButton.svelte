<script lang="ts">
  import { getContext } from "svelte";
  import {
    OIDC_CONTEXT_CLIENT_PROMISE,
    refreshToken,
    tokenRefresh,
  } from "./Keycloak.svelte";
  import type { OidcContextClientPromise } from "../types";
  import { config } from "../../config";

  const oidcAuthPromise: OidcContextClientPromise = getContext(
    OIDC_CONTEXT_CLIENT_PROMISE
  );

  let _class = "btn btn-primary";
  export { _class as class };
</script>

<button
  class={_class}
  on:click|preventDefault={() =>
    tokenRefresh(oidcAuthPromise, $refreshToken, config.oidc.refreshTokenEndpoint, "refresh button")}
>
  <slot />
</button>
