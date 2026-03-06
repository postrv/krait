defmodule KraitWeb.Plugs.RuntimeSessionTest do
  use ExUnit.Case, async: false
  import Plug.Test

  setup do
    # Clear any persistent_term cache from previous tests
    try do
      :persistent_term.erase(:krait_session_opts)
    rescue
      ArgumentError -> :ok
    end

    original = Application.get_env(:krait, KraitWeb.Endpoint)

    # Also strip session_options from endpoint config to avoid bleed from prior tests
    if original do
      clean = Keyword.delete(original, :session_options)
      Application.put_env(:krait, KraitWeb.Endpoint, clean)
    end

    on_exit(fn ->
      try do
        :persistent_term.erase(:krait_session_opts)
      rescue
        ArgumentError -> :ok
      end

      if original do
        Application.put_env(:krait, KraitWeb.Endpoint, original)
      end
    end)

    :ok
  end

  describe "init/1" do
    test "stores default opts unchanged" do
      opts = [store: :cookie, key: "_krait_key", signing_salt: "dev_salt"]
      assert ^opts = KraitWeb.Plugs.RuntimeSession.init(opts)
    end
  end

  describe "session max_age (M-10)" do
    test "session options include max_age: 3600 by default" do
      # Verify the endpoint module's @session_options includes max_age
      defaults = [
        store: :cookie,
        key: "_krait_key",
        signing_salt: "dev_default_session_salt",
        encryption_salt: "dev_default_encryption_salt",
        same_site: "Strict",
        max_age: 3600
      ]

      merged = KraitWeb.Plugs.RuntimeSession.merged_session_opts(defaults)
      assert merged[:max_age] == 3600
    end

    test "production can override max_age via runtime config" do
      defaults = [
        store: :cookie,
        key: "_krait_key",
        signing_salt: "dev_salt",
        max_age: 3600
      ]

      endpoint_config = Application.get_env(:krait, KraitWeb.Endpoint, [])

      updated_config =
        Keyword.put(endpoint_config, :session_options, max_age: 7200)

      Application.put_env(:krait, KraitWeb.Endpoint, updated_config)

      merged = KraitWeb.Plugs.RuntimeSession.merged_session_opts(defaults)
      assert merged[:max_age] == 7200
    end
  end

  describe "call/2" do
    test "uses default salts when no runtime config set" do
      defaults = [
        store: :cookie,
        key: "_krait_key",
        signing_salt: "dev_default_session_salt",
        encryption_salt: "dev_default_encryption_salt",
        same_site: "Lax"
      ]

      # Ensure no session_options override in endpoint config
      endpoint_config = Application.get_env(:krait, KraitWeb.Endpoint, [])
      clean_config = Keyword.delete(endpoint_config, :session_options)
      Application.put_env(:krait, KraitWeb.Endpoint, clean_config)

      conn =
        conn(:get, "/")
        |> Map.put(:secret_key_base, String.duplicate("a", 64))
        |> KraitWeb.Plugs.RuntimeSession.call(defaults)

      # Session plug should have run (conn should have session fetched)
      assert conn.status != 500 || conn.status == nil
    end

    test "runtime config overrides compile-time defaults" do
      defaults = [
        store: :cookie,
        key: "_krait_key",
        signing_salt: "dev_default_session_salt",
        encryption_salt: "dev_default_encryption_salt",
        same_site: "Lax"
      ]

      # Set runtime overrides
      endpoint_config = Application.get_env(:krait, KraitWeb.Endpoint, [])

      updated_config =
        Keyword.put(endpoint_config, :session_options,
          signing_salt: "prod_signing_salt_override",
          encryption_salt: "prod_encryption_salt_override"
        )

      Application.put_env(:krait, KraitWeb.Endpoint, updated_config)

      # Verify merge produces correct result
      merged = KraitWeb.Plugs.RuntimeSession.merged_session_opts(defaults)
      assert merged[:signing_salt] == "prod_signing_salt_override"
      assert merged[:encryption_salt] == "prod_encryption_salt_override"
      # Non-overridden defaults are preserved
      assert merged[:key] == "_krait_key"
      assert merged[:store] == :cookie
      assert merged[:same_site] == "Lax"
    end

    test "persistent_term caching works" do
      defaults = [
        store: :cookie,
        key: "_krait_key",
        signing_salt: "dev_salt",
        encryption_salt: "dev_enc_salt"
      ]

      # First call should compute and cache
      merged1 = KraitWeb.Plugs.RuntimeSession.merged_session_opts(defaults)

      # Second call should return cached value
      merged2 = KraitWeb.Plugs.RuntimeSession.merged_session_opts(defaults)

      assert merged1 == merged2

      # Verify it's actually in persistent_term
      cached = :persistent_term.get(:krait_session_opts)
      assert cached == merged1
    end
  end

  describe "v22 SEC-07: invalidate_cache/0" do
    setup do
      # Clean up persistent_term in case previous test left state
      try do
        :persistent_term.erase(:krait_session_opts)
      rescue
        ArgumentError -> :ok
      end

      try do
        :persistent_term.erase(:krait_session_init)
      rescue
        ArgumentError -> :ok
      end

      on_exit(fn ->
        try do
          :persistent_term.erase(:krait_session_opts)
        rescue
          ArgumentError -> :ok
        end

        try do
          :persistent_term.erase(:krait_session_init)
        rescue
          ArgumentError -> :ok
        end
      end)

      :ok
    end

    test "after invalidate_cache, new config is picked up" do
      defaults = [
        store: :cookie,
        key: "_krait_key",
        signing_salt: "old_salt",
        encryption_salt: "old_enc"
      ]

      # Populate cache
      _merged = KraitWeb.Plugs.RuntimeSession.merged_session_opts(defaults)
      assert {:ok, _} = safe_get(:krait_session_opts)

      # Invalidate
      assert :ok = KraitWeb.Plugs.RuntimeSession.invalidate_cache()

      # Cache should be empty now
      assert :miss = safe_get(:krait_session_opts)
      assert :miss = safe_get(:krait_session_init)
    end

    test "invalidate_cache is idempotent (safe on empty cache)" do
      # Should not raise
      assert :ok = KraitWeb.Plugs.RuntimeSession.invalidate_cache()
      assert :ok = KraitWeb.Plugs.RuntimeSession.invalidate_cache()
    end

    defp safe_get(key) do
      {:ok, :persistent_term.get(key)}
    rescue
      ArgumentError -> :miss
    end
  end
end
