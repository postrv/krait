defmodule Krait.Security.PathResolverTest do
  use ExUnit.Case, async: true

  alias Krait.Security.PathResolver

  @moduletag :tmp_dir

  describe "safe_realpath/1" do
    test "resolves regular file path", %{tmp_dir: tmp_dir} do
      file = Path.join(tmp_dir, "regular_file.txt")
      File.write!(file, "content")

      assert {:ok, resolved} = PathResolver.safe_realpath(file)
      assert resolved == file
    end

    test "resolves single symlink", %{tmp_dir: tmp_dir} do
      target = Path.join(tmp_dir, "target.txt")
      link = Path.join(tmp_dir, "link.txt")
      File.write!(target, "content")
      File.ln_s!(target, link)

      assert {:ok, resolved} = PathResolver.safe_realpath(link)
      assert resolved == target
    end

    test "follows chain of symlinks (3 hops)", %{tmp_dir: tmp_dir} do
      target = Path.join(tmp_dir, "final.txt")
      link1 = Path.join(tmp_dir, "link1.txt")
      link2 = Path.join(tmp_dir, "link2.txt")
      link3 = Path.join(tmp_dir, "link3.txt")
      File.write!(target, "content")
      File.ln_s!(target, link1)
      File.ln_s!(link1, link2)
      File.ln_s!(link2, link3)

      assert {:ok, resolved} = PathResolver.safe_realpath(link3)
      assert resolved == target
    end

    test "returns {:error, :symlink_loop} for circular symlinks", %{tmp_dir: tmp_dir} do
      link_a = Path.join(tmp_dir, "a.txt")
      link_b = Path.join(tmp_dir, "b.txt")
      File.ln_s!(link_b, link_a)
      File.ln_s!(link_a, link_b)

      assert {:error, :symlink_loop} = PathResolver.safe_realpath(link_a)
    end

    test "returns {:error, :enoent} for non-existent paths" do
      assert {:error, :enoent} = PathResolver.safe_realpath("/nonexistent/path/file.txt")
    end

    test "resolves relative symlink targets", %{tmp_dir: tmp_dir} do
      subdir = Path.join(tmp_dir, "subdir")
      File.mkdir_p!(subdir)
      target = Path.join(subdir, "target.txt")
      File.write!(target, "content")

      # Create a symlink with a relative target
      link = Path.join(tmp_dir, "relative_link.txt")
      File.ln_s!("subdir/target.txt", link)

      assert {:ok, resolved} = PathResolver.safe_realpath(link)
      assert resolved == target
    end
  end

  describe "path_within?/2" do
    test "validates containment for regular paths", %{tmp_dir: tmp_dir} do
      subdir = Path.join(tmp_dir, "sub")
      File.mkdir_p!(subdir)
      file = Path.join(subdir, "file.txt")
      File.write!(file, "content")

      assert PathResolver.path_within?(file, tmp_dir)
    end

    test "rejects symlink escape", %{tmp_dir: tmp_dir} do
      # Create an escape symlink that points outside tmp_dir
      escape_target = System.tmp_dir!() |> Path.join("escape_target_#{:rand.uniform(100_000)}")
      File.write!(escape_target, "escaped")

      on_exit(fn -> File.rm(escape_target) end)

      link = Path.join(tmp_dir, "escape_link.txt")
      File.ln_s!(escape_target, link)

      refute PathResolver.path_within?(link, tmp_dir)
    end
  end
end
