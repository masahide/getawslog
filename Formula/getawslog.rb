class Getawslog < Formula
  desc "AWS assume role credential wrapper"
  homepage "https://github.com/masahide/getawslog"
  url "https://github.com/masahide/getawslog/releases/download/v0.1.0/getawslog_Darwin_x86_64.tar.gz"
  version "0.1.0"
  sha256 "ff03bc58610a4213a7c94cfeb37b4907f2777499ae0438f2696c6a69d63e2c61"

  def install
    bin.install "getawslog"
  end

  test do
    system "#{bin}/getawslog -v"
  end
end
