<script lang="ts">
  import { browser } from "$app/env";
  import { session, page } from "$app/stores";
  import { getContext } from "svelte";
  import { OIDC_CONTEXT_CLIENT_PROMISE } from "./Keycloak.svelte";
  import type { OidcContextClientPromise } from "../types";
  import { isTokenExpired } from "./jwt";
  import debug from "debug";

  const log = debug("sveltekit-oidc:ProtectedRoute");

  let isAuthenticated = false;

  const loadUser = async () => {
    if (browser) {
      const oidcPromise: OidcContextClientPromise = getContext(
        OIDC_CONTEXT_CLIENT_PROMISE
      );
      const oidc_func = await oidcPromise;
      const { redirect } = oidc_func($page.url.pathname, $page.params);
      if (
        !($session as any)?.user ||
        !($session as any)?.access_token ||
        !($session as any)?.user
      ) {
        try {
          log(redirect);
          window.location.assign(redirect);
        } catch (e) {
          console.error(e);
        }
      } else {
        if (isTokenExpired(($session as any).access_token)) {
          log(redirect);
          window.location.assign(redirect);
        }
        isAuthenticated = true;
      }
    }
  };
</script>

{#await loadUser()}
  <p>Loading...</p>
{:then}
  {#if isAuthenticated}
    <slot />
  {/if}
{/await}
