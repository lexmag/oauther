defmodule OAuther.Mixfile do
  use Mix.Project

  def project() do
    [
      app: :oauther,
      version: "1.1.1",
      elixir: ">= 0.14.1",
      description: description(),
      package: package()
    ]
  end

  def application() do
    [extra_applications: [:crypto, :public_key]]
  end

  defp description() do
    "Library to authenticate with OAuth 1.0 protocol."
  end

  defp package() do
    [
      files: ["lib", "mix.exs", "README.md", "LICENSE"],
      maintainers: ["Aleksei Magusev"],
      licenses: ["ISC"],
      links: %{"GitHub" => "https://github.com/lexmag/oauther"}
    ]
  end
end
