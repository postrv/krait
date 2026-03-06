defmodule Krait.Sandbox.V26DockerBackendTest do
  use ExUnit.Case, async: true

  alias Krait.Sandbox.DockerBackend

  describe "validate_network!/1" do
    test "accepts 'none'" do
      assert DockerBackend.validate_network!("none") == nil
    end

    test "accepts 'bridge'" do
      assert DockerBackend.validate_network!("bridge") == nil
    end

    test "rejects 'host'" do
      assert_raise ArgumentError, ~r/invalid Docker network mode/, fn ->
        DockerBackend.validate_network!("host")
      end
    end

    test "rejects arbitrary network name" do
      assert_raise ArgumentError, ~r/invalid Docker network mode/, fn ->
        DockerBackend.validate_network!("my-custom-net")
      end
    end

    test "rejects non-binary input" do
      assert_raise ArgumentError, ~r/invalid Docker network mode/, fn ->
        DockerBackend.validate_network!(nil)
      end
    end
  end

  describe "init/1 network validation" do
    test "rejects host network mode" do
      assert_raise ArgumentError, ~r/invalid Docker network mode/, fn ->
        DockerBackend.init(network: "host")
      end
    end

    test "accepts none network mode" do
      assert {:ok, state} = DockerBackend.init(network: "none")
      assert state.network == "none"
    end

    test "defaults to none" do
      assert {:ok, state} = DockerBackend.init([])
      assert state.network == "none"
    end
  end
end
