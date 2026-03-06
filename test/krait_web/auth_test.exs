defmodule KraitWeb.AuthTest do
  use ExUnit.Case, async: false

  describe "admin_token/0" do
    setup do
      prev_admin = Application.get_env(:krait, :admin_auth_token)
      prev_api = Application.get_env(:krait, :api_auth_token)

      on_exit(fn ->
        if prev_admin,
          do: Application.put_env(:krait, :admin_auth_token, prev_admin),
          else: Application.delete_env(:krait, :admin_auth_token)

        if prev_api,
          do: Application.put_env(:krait, :api_auth_token, prev_api),
          else: Application.delete_env(:krait, :api_auth_token)
      end)

      :ok
    end

    test "returns :admin_auth_token when set" do
      Application.put_env(:krait, :admin_auth_token, "admin-secret")
      Application.put_env(:krait, :api_auth_token, "api-secret")

      assert KraitWeb.Auth.admin_token() == "admin-secret"
    end

    test "v23 H-4: returns nil when admin_auth_token is not set (no fallback)" do
      Application.delete_env(:krait, :admin_auth_token)
      Application.put_env(:krait, :api_auth_token, "api-secret")

      assert KraitWeb.Auth.admin_token() == nil
    end

    test "v23 H-4: returns nil when admin_auth_token is empty string" do
      Application.put_env(:krait, :admin_auth_token, "")
      Application.put_env(:krait, :api_auth_token, "api-secret")

      assert KraitWeb.Auth.admin_token() == nil
    end

    test "returns nil when both tokens are nil" do
      Application.delete_env(:krait, :admin_auth_token)
      Application.delete_env(:krait, :api_auth_token)

      assert KraitWeb.Auth.admin_token() == nil
    end
  end
end
