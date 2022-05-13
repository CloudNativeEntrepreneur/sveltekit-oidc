<script lang="ts">
  import { session } from "$app/stores";
  import { ProtectedRoute, LogoutButton } from "$lib";
</script>

<ProtectedRoute>
  <div
    class="h-screen-minus-navbar bg-gray-800 text-white flex flex-col justify-center items-center w-full"
  >
    <h1>Your Profile</h1>
    <p><strong>Email:</strong> {$session.user?.email}</p>
    <p><strong>Username:</strong> {$session.user?.preferred_username}</p>
    {#if $session.user["https://hasura.io/jwt/claims"]["x-hasura-allowed-roles"]}
      <div>
        <strong>Your roles:</strong>
        <ul>
          {#each $session.user["https://hasura.io/jwt/claims"]["x-hasura-allowed-roles"] as role}
            <li>{role}</li>
          {/each}
        </ul>
      </div>
    {/if}
    <LogoutButton>Logout</LogoutButton>
  </div>
</ProtectedRoute>
