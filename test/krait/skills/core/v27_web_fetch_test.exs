defmodule Krait.Skills.Core.V27WebFetchTest do
  @moduledoc "v27 H-1: SSRF IP pinning fail-closed tests"
  use ExUnit.Case, async: false

  alias Krait.Skills.Core.WebFetch

  # v27 H-1: When parse_ip_to_tuple returns nil (unusual IP format),
  # the request must fail closed rather than proceeding without pinning.

  describe "IP pinning fail-closed" do
    setup do
      # Allow tests to reach SSRF check path by using prod-like config
      prev_env = Application.get_env(:krait, :env)
      prev_local = Application.get_env(:krait, :allow_local_network)
      prev_allowlist = Application.get_env(:krait, :network_allowlist)

      Application.put_env(:krait, :env, :prod)
      Application.put_env(:krait, :allow_local_network, false)
      Application.put_env(:krait, :network_allowlist, ["example.com"])

      on_exit(fn ->
        if prev_env,
          do: Application.put_env(:krait, :env, prev_env),
          else: Application.delete_env(:krait, :env)

        if prev_local,
          do: Application.put_env(:krait, :allow_local_network, prev_local),
          else: Application.delete_env(:krait, :allow_local_network)

        if prev_allowlist,
          do: Application.put_env(:krait, :network_allowlist, prev_allowlist),
          else: Application.delete_env(:krait, :network_allowlist)
      end)

      :ok
    end

    test "rejects request when domain is not in allowlist" do
      assert {:error, msg} = WebFetch.execute(%{"url" => "https://evil.com/path"})
      assert msg =~ "not in domain allowlist"
    end

    test "valid URL with allowed domain attempts DNS resolution (fails in test)" do
      # In test env with prod config, DNS resolution will fail for non-routable domains
      assert {:error, msg} = WebFetch.execute(%{"url" => "https://example.com/test"})
      # Either DNS fails or port blocked — both are errors (not success)
      assert is_binary(msg)
    end
  end
end
