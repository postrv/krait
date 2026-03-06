defmodule KraitWeb.EndpointTest do
  use ExUnit.Case, async: false

  setup do
    # Clear persistent_term cache between tests
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

    :ok
  end

  test "session_options/0 returns keyword list with required keys" do
    opts = KraitWeb.Endpoint.session_options()
    assert is_list(opts)
    assert Keyword.has_key?(opts, :store)
    assert Keyword.has_key?(opts, :key)
    assert Keyword.has_key?(opts, :signing_salt)
    assert Keyword.has_key?(opts, :encryption_salt)
  end

  test "session_options/0 merges runtime :session_options from Endpoint config" do
    original = Application.get_env(:krait, KraitWeb.Endpoint)

    endpoint_config = Application.get_env(:krait, KraitWeb.Endpoint, [])

    updated =
      Keyword.put(endpoint_config, :session_options,
        signing_salt: "runtime_signing",
        encryption_salt: "runtime_encryption"
      )

    Application.put_env(:krait, KraitWeb.Endpoint, updated)

    opts = KraitWeb.Endpoint.session_options()
    assert opts[:signing_salt] == "runtime_signing"
    assert opts[:encryption_salt] == "runtime_encryption"
    # Compile-time defaults preserved for non-overridden keys
    assert opts[:key] == "_krait_key"
    assert opts[:store] == :cookie

    # Restore
    if original do
      Application.put_env(:krait, KraitWeb.Endpoint, original)
    end
  end
end
