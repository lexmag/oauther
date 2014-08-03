defmodule OAuther.Mixfile do
  use Mix.Project

  def project do
    [app: :oauther,
     version: "1.0.1",
     elixir: ">= 0.14.1",
     description: description,
     package: package]
  end

  def application do
    [applications: []]
  end

  defp description,
    do: "Library to authenticate with OAuth 1.0 protocol."

  defp package do
    [files: ["lib", "mix.exs", "README.md", "LICENSE"],
     contributors: ["Aleksei Magusev"],
     licenses: ["ISC"],
     links: %{"GitHub" => "https://github.com/lexmag/oauther"}]
  end
end
