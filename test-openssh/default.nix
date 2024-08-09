{ pkgs ? import <nixpkgs> { }, ... }:
let
  optimizeWithFlags = pkg: flags:
    pkgs.lib.overrideDerivation pkg (old:
      let
        newflags = pkgs.lib.foldl' (acc: x: "${acc} ${x}") "" flags;
        oldflags =
          if (pkgs.lib.hasAttr "NIX_CFLAGS_COMPILE" old)
          then "${old.NIX_CFLAGS_COMPILE}"
          else "";
      in
      {
        CFLAGS = "-DDEBUG_KEXDH -DDEBUG_KEX -DDEBUG_KEXECDH";
        NIX_CFLAGS_COMPILE = "${oldflags} ${newflags}";
        checkPhase = "";
        doCheck = false;
      });
in
optimizeWithFlags pkgs.openssh [ "-DDEBUG_KEXDH" ]
