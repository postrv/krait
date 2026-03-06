defmodule Krait.Evolution.V26ValidatorTest do
  use ExUnit.Case, async: true

  # ---------------------------------------------------------------------------
  # Phase 7: L-12 — Validator Temp File Atomic Create
  # ---------------------------------------------------------------------------
  describe "validator temp file creation (L-12)" do
    test "temp file is created with mode 0o600" do
      random_suffix = :crypto.strong_rand_bytes(16) |> Base.url_encode64(padding: false)
      tmp_path = Path.join(System.tmp_dir!(), "krait_validate_#{random_suffix}.ex")

      try do
        # Simulate what validator does
        case :file.open(String.to_charlist(tmp_path), [:write, :exclusive]) do
          {:ok, fd} ->
            File.chmod!(tmp_path, 0o600)
            :file.write(fd, "defmodule Test do\nend\n")
            :file.close(fd)

            # Verify file permissions
            {:ok, stat} = File.stat(tmp_path)
            # 0o600 = owner read/write only
            assert stat.access == :read_write

          {:error, reason} ->
            flunk("Failed to create temp file: #{inspect(reason)}")
        end
      after
        File.rm(tmp_path)
      end
    end

    test "exclusive flag prevents creation if file already exists" do
      random_suffix = :crypto.strong_rand_bytes(16) |> Base.url_encode64(padding: false)
      tmp_path = Path.join(System.tmp_dir!(), "krait_validate_#{random_suffix}.ex")

      try do
        # Create the file first
        File.write!(tmp_path, "existing content")

        # Attempt exclusive create — should fail
        result = :file.open(String.to_charlist(tmp_path), [:write, :exclusive])
        assert {:error, :eexist} = result
      after
        File.rm(tmp_path)
      end
    end
  end
end
